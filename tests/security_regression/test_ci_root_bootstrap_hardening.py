import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_ENTRYPOINTS = (
    "ci/provisioning/build-v3-under-src.sh",
    "ci/provisioning/check-v3-api-smoke-prereqs.sh",
    "ci/provisioning/fetch-crs.sh",
    "ci/provisioning/fetch-smoke-sources.sh",
    "ci/provisioning/find-modsecurity-v3.sh",
    "ci/provisioning/generate-mrts.sh",
    "ci/provisioning/materialize-connector-source.sh",
    "ci/provisioning/prepare-apache-build.sh",
    "ci/provisioning/prepare-crs.sh",
    "ci/provisioning/prepare-envoy-runtime.sh",
    "ci/provisioning/prepare-haproxy-runtime.sh",
    "ci/provisioning/prepare-lighttpd-runtime.sh",
    "ci/provisioning/prepare-nginx-build.sh",
    "ci/provisioning/prepare-traefik-runtime.sh",
    "ci/provisioning/write-mrts-load.sh",
    "ci/runtime/probe-response-body-blocking.sh",
    "ci/runtime/run-apache-smoke.sh",
    "ci/runtime/run-connector-smokes.sh",
    "ci/runtime/run-connector-starter-checks.sh",
    "ci/runtime/run-envoy-smoke.sh",
    "ci/runtime/run-haproxy-runtime-matrix.sh",
    "ci/runtime/run-haproxy-smoke.sh",
    "ci/runtime/run-lighttpd-smoke.sh",
    "ci/runtime/run-nginx-smoke.sh",
    "ci/runtime/run-runtime-matrix.sh",
    "ci/runtime/run-traefik-smoke.sh",
    "ci/runtime/run-v3-api-smoke.sh",
    "ci/runtime/smoke-installed.sh",
)
CATALOG_BOOTSTRAP_ENTRYPOINTS = (
    "ci/checks/catalog/check-adapter-helpers.sh",
    "ci/checks/catalog/check-adapter-metadata-drift.sh",
    "ci/checks/catalog/check-common-helpers.sh",
    "ci/checks/catalog/check-crs-version-pinning.sh",
    "ci/checks/catalog/check-open-runtime-provisioning-contract.sh",
)


class CiRootBootstrapHardeningTests(unittest.TestCase):
    def run_script(self, script: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(environment)
        return subprocess.run(
            ["sh", str(script)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def run_shell(self, script: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(environment)
        return subprocess.run(
            ["sh", "-c", script],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def write_foreign_ci(self, root: Path, marker: Path, *, common_body: str) -> Path:
        foreign_ci = root / "foreign" / "ci"
        lib = foreign_ci / "lib"
        lib.mkdir(parents=True)
        (lib / "path-bootstrap.sh").write_text(
            f"touch {shlex.quote(str(marker))}\n",
            encoding="utf-8",
        )
        (lib / "path.sh").write_text(
            f"touch {shlex.quote(str(marker))}\n"
            "ci_init_paths() { return 0; }\n",
            encoding="utf-8",
        )
        (lib / "common.sh").write_text(common_body, encoding="utf-8")
        (lib / "connector-smoke-common.sh").write_text(common_body, encoding="utf-8")
        return foreign_ci

    def test_all_direct_entrypoints_source_bootstrap_relative_to_their_script(self) -> None:
        entrypoints = [
            (relative_path, '. "$SCRIPT_DIR/../lib/path-bootstrap.sh"')
            for relative_path in BOOTSTRAP_ENTRYPOINTS
        ]
        entrypoints.extend(
            (relative_path, '. "$SCRIPT_DIR/../../lib/path-bootstrap.sh"')
            for relative_path in CATALOG_BOOTSTRAP_ENTRYPOINTS
        )
        for relative_path, expected_source in entrypoints:
            with self.subTest(entrypoint=relative_path):
                source = (ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn(expected_source, source)
                self.assertNotIn('. "$CI_ROOT/lib/path-bootstrap.sh"', source)

    def test_common_workflow_materializes_inside_the_verified_run_root(self) -> None:
        workflow = (ROOT / ".github/workflows/test-common.yml").read_text(encoding="utf-8")
        self.assertIn('out="$VERIFIED_RUN_ROOT/case-runner"', workflow)
        self.assertNotIn('out="$RUNNER_TEMP/case-runner"', workflow)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            verified_root = temporary_root / "verified"
            case_output = verified_root / "case-runner" / "audit-log"
            case_output.mkdir(parents=True, mode=0o700)
            case_output.chmod(0o700)
            (case_output / "audit").mkdir(mode=0o700)
            environment = os.environ.copy()
            environment.update(
                {
                    "BUILD_ROOT": "",
                    "MODSECURITY_RULE_PREAMBLE_FILE": "",
                    "VERIFIED_RUN_ROOT": str(verified_root),
                }
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tests/runners/case_cli.py"),
                    "materialize",
                    "--case",
                    str(ROOT / "tests/cases/audit-log/audit_log_phase1_block.yaml"),
                    "--rules-file",
                    str(case_output / "rules.conf"),
                    "--env-file",
                    str(case_output / "case.env"),
                    "--headers-file",
                    str(case_output / "request-headers.txt"),
                    "--body-file",
                    str(case_output / "request-body.bin"),
                    "--docroot",
                    str(case_output / "htdocs"),
                    "--audit-log-file",
                    str(case_output / "audit.log"),
                    "--audit-log-dir",
                    str(case_output / "audit"),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((case_output / "rules.conf").is_file())

    def test_common_source_does_not_resolve_a_caller_env_function(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            marker = Path(temporary_directory) / "env-function-ran"
            result = self.run_shell(
                "\n".join(
                    (
                        'env() { printf used > "$ENV_FUNCTION_MARKER"; /usr/bin/env; }',
                        '. "$COMMON_SH"',
                        'test ! -e "$ENV_FUNCTION_MARKER"',
                    )
                ),
                {
                    "COMMON_SH": str(ROOT / "ci/lib/common.sh"),
                    "ENV_FUNCTION_MARKER": str(marker),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)

    def test_top_level_make_does_not_expand_python_cache_prefix_before_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            marker = Path(temporary_directory) / "python-cache-prefix-eval-ran"
            result = subprocess.run(
                [
                    "make",
                    "-n",
                    "check-canonical-common-pins",
                    f"PYTHONPYCACHEPREFIX=/tmp/$(shell touch {marker})",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("unsupported shell syntax", result.stdout + result.stderr)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)

    def test_top_level_make_rejects_shell_syntax_in_recipe_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            cases = (
                ("BUILD_ROOT", f"/tmp/`touch {temporary_root / 'build-backtick'}`"),
                ("TMP_ROOT", f"/tmp/\";touch {temporary_root / 'tmp-quote'};#"),
                ("PYTHON", f"/tmp/`touch {temporary_root / 'python-backtick'}`"),
            )
            for variable, payload in cases:
                with self.subTest(variable=variable):
                    result = subprocess.run(
                        ["make", "-n", "check-canonical-common-pins", f"{variable}={payload}"],
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("unsupported shell syntax", result.stdout + result.stderr)
                    self.assertFalse(any(temporary_root.iterdir()))

            legitimate = subprocess.run(
                [
                    "make",
                    "-n",
                    "check-canonical-common-pins",
                    f"BUILD_ROOT={temporary_root / 'build'}",
                    f"TMP_ROOT={temporary_root / 'tmp'}",
                    "PYTHON=python3",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(legitimate.returncode, 0, legitimate.stdout + legitimate.stderr)
            self.assertNotIn("unsupported shell syntax", legitimate.stdout + legitimate.stderr)

    def test_top_level_make_rejects_shell_syntax_in_tool_and_artifact_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            variables = (
                "WORKFLOW_SECURITY_TOOL",
                "PYTHON_VERSION_CONTRACT_TOOL",
                "FULL_LIFECYCLE_EVIDENCE_TOOL",
                "TRANSPORT_HARDENING_EVIDENCE_TOOL",
                "PROTOCOL_CLIENT_TOOL",
                "PROTOCOL_EVIDENCE_TOOL",
                "CONNECTOR",
                "NO_CRS_RUN_ID",
                "EVIDENCE_STAGE",
                "NO_CRS_ARTIFACT_PROFILE",
                "PLAN_FILE",
                "NO_CRS_SUMMARY_ROOT",
                "REPORTS_DIR",
                "CI_SHELL_FILES",
                "CI_PYTHON_FILES",
                "HOME",
                "XDG_STATE_HOME",
                "PROTOCOL_STRICT",
                "PROTOCOL_INSECURE",
                "PROTOCOL_QUIC_UDP_OBSERVED",
                "SKIP_ROOT_SUMMARY",
            )
            for variable in variables:
                marker = temporary_root / f"{variable.lower()}-ran"
                payload = f"/tmp/`touch {marker}`"
                with self.subTest(variable=variable):
                    result = subprocess.run(
                        ["make", "-n", "check-canonical-common-pins", f"{variable}={payload}"],
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("unsupported shell syntax", result.stdout + result.stderr)
                    self.assertFalse(marker.exists(), result.stdout + result.stderr)

            legitimate = subprocess.run(
                [
                    "make",
                    "-n",
                    "check-canonical-common-pins",
                    f"WORKFLOW_SECURITY_TOOL={ROOT / 'ci/checks/security/check-github-actions-workflows.py'}",
                    f"PROTOCOL_EVIDENCE_TOOL={ROOT / 'ci/checks/protocol/check_protocol_evidence.py'}",
                    f"PLAN_FILE={temporary_root / 'plan.json'}",
                    f"NO_CRS_SUMMARY_ROOT={temporary_root / 'summary'}",
                    "CONNECTOR=apache",
                    "NO_CRS_RUN_ID=run-1",
                    "EVIDENCE_STAGE=no_crs_baseline",
                    "NO_CRS_ARTIFACT_PROFILE=generic",
                    "PROTOCOL_STRICT=0",
                    "PROTOCOL_INSECURE=1",
                    "PROTOCOL_QUIC_UDP_OBSERVED=yes",
                    "SKIP_ROOT_SUMMARY=1",
                    "PYTHON=python3",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(legitimate.returncode, 0, legitimate.stdout + legitimate.stderr)
            self.assertNotIn("unsupported shell syntax", legitimate.stdout + legitimate.stderr)

    def test_safe_make_clears_pre_parser_flags_and_forces_recursive_make(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            marker = Path(temporary_directory) / "make-pre-parser-ran"
            injection = f"--eval=$(shell touch {marker})"
            environment = os.environ.copy()
            environment.update(
                {
                    "MAKEFLAGS": injection,
                    "GNUMAKEFLAGS": injection,
                    "MAKEFILES": str(marker),
                    "MAKEOVERRIDES": "MAKE=/bin/true",
                    "MAKE": "/bin/true",
                }
            )
            result = subprocess.run(
                [str(ROOT / "ci/tools/safe-make.sh"), "-n", "check-canonical-common-pins"],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)

            recursive = subprocess.run(
                [str(ROOT / "ci/tools/safe-make.sh"), "-n", "test-makefile-contract"],
                cwd=ROOT,
                env={**environment, "MAKEFLAGS": "", "GNUMAKEFLAGS": ""},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(recursive.returncode, 0, recursive.stdout + recursive.stderr)
            self.assertIn("python -m unittest discover -s tests/makefile_contract", recursive.stdout)

            argv_injection = subprocess.run(
                [
                    str(ROOT / "ci/tools/safe-make.sh"),
                    "-n",
                    "MAKEFLAGS=--eval=$(warning argv-eval-ran)",
                    "check-canonical-common-pins",
                ],
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin"},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(argv_injection.returncode, 77, argv_injection.stdout + argv_injection.stderr)
            self.assertIn("control-variable assignments", argv_injection.stderr)
            self.assertNotIn("argv-eval-ran", argv_injection.stdout + argv_injection.stderr)

            for assignment in (
                "MAKEFLAGS+=--eval=$(warning append-eval-ran)",
                "GNUMAKEFLAGS?=--eval=$(warning conditional-eval-ran)",
                "MAKEOVERRIDES:=--eval=$(warning simple-eval-ran)",
                "MFLAGS!=--eval=$(warning shell-eval-ran)",
            ):
                with self.subTest(assignment=assignment):
                    rejected = subprocess.run(
                        [str(ROOT / "ci/tools/safe-make.sh"), "-n", assignment, "check-canonical-common-pins"],
                        cwd=ROOT,
                        env={"PATH": "/usr/bin:/bin"},
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(rejected.returncode, 77, rejected.stdout + rejected.stderr)
                    self.assertNotIn("eval-ran", rejected.stdout + rejected.stderr)

            for option in ("--eval=$(warning eval-ran)", "-E$(warning short-eval-ran)", "--file=/tmp/untrusted.mk", "-C/tmp", "-e"):
                with self.subTest(option=option):
                    rejected = subprocess.run(
                        [str(ROOT / "ci/tools/safe-make.sh"), "-n", option, "check-canonical-common-pins"],
                        cwd=ROOT,
                        env={"PATH": "/usr/bin:/bin"},
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(rejected.returncode, 77, rejected.stdout + rejected.stderr)

            legitimate = subprocess.run(
                [
                    str(ROOT / "ci/tools/safe-make.sh"),
                    "-n",
                    "-j2",
                    "PYTHON=python3",
                    "check-canonical-common-pins",
                ],
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin"},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(legitimate.returncode, 0, legitimate.stdout + legitimate.stderr)

    def test_common_source_clears_make_control_environment_for_child_calls(self) -> None:
        result = self.run_shell(
            ". \"$COMMON_SH\"\n"
            "test -z \"${MAKEFLAGS:-}\"\n"
            "test -z \"${GNUMAKEFLAGS:-}\"\n"
            "test -z \"${MAKEFILES:-}\"\n"
            "test -z \"${MAKEOVERRIDES:-}\"\n"
            "test -z \"${MAKE:-}\"\n",
            {
                "COMMON_SH": str(ROOT / "ci/lib/common.sh"),
                "MAKEFLAGS": "--eval=$(shell touch /var/tmp/make-common-should-not-run)",
                "GNUMAKEFLAGS": "--eval=$(shell touch /var/tmp/gnumake-common-should-not-run)",
                "MAKEFILES": "/tmp/untrusted-makefile",
                "MAKEOVERRIDES": "MAKE=/bin/true",
                "MAKE": "/bin/true",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_prepare_crs_rejects_source_and_runtime_paths_outside_task_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            verified_root = temporary_root / "verified"
            source_root = verified_root / "source"
            build_root = verified_root / "build"
            approved_source = source_root / "coreruleset"
            (approved_source / "rules").mkdir(parents=True)
            (approved_source / "crs-setup.conf.example").write_text("SecRuleEngine On\n", encoding="utf-8")
            (approved_source / "rules" / "REQUEST-901-INITIALIZATION.conf").write_text("# rules\n", encoding="utf-8")
            base_environment = {
                "VERIFIED_RUN_ROOT": str(verified_root),
                "SOURCE_ROOT": str(source_root),
                "BUILD_ROOT": str(build_root),
                "TMP_ROOT": str(build_root / "tmp"),
                "LOG_ROOT": str(build_root / "logs"),
                "CRS_RUNTIME_DIR": str(build_root / "crs"),
            }

            for label, source_dir, runtime_dir in (
                ("source", verified_root / "unapproved-source", build_root / "crs"),
                ("runtime", approved_source, verified_root / "unapproved-runtime"),
            ):
                with self.subTest(path=label):
                    result = self.run_script(
                        ROOT / "ci/provisioning/prepare-crs.sh",
                        {
                            **base_environment,
                            "CRS_SOURCE_DIR": str(source_dir),
                            "CRS_RUNTIME_DIR": str(runtime_dir),
                        },
                    )
                    self.assertEqual(result.returncode, 77, result.stderr)
                    self.assertFalse(runtime_dir.exists())

    def test_crs_and_haproxy_preparers_reject_inherited_pin_overrides_before_sinks(self) -> None:
        cases = (
            (
                ROOT / "ci/provisioning/prepare-crs.sh",
                {"CRS_GIT_REF": "unreviewed-ref"},
                "CRS_GIT_REF override is not permitted",
            ),
            (
                ROOT / "ci/provisioning/prepare-haproxy-runtime.sh",
                {"HAPROXY_VERSION": "0.0.0-unreviewed"},
                "HAPROXY_VERSION override is not permitted",
            ),
        )
        for script, overrides, expected in cases:
            with self.subTest(script=script.name):
                result = self.run_script(script, overrides)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertIn(expected, result.stdout + result.stderr)

    def test_prepare_lighttpd_rejects_private_build_root_outside_task_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            verified_root = temporary_root / "verified"
            build_root = verified_root / "build"
            foreign_private_root = temporary_root / "foreign-private-lighttpd-build"
            result = self.run_script(
                ROOT / "ci/provisioning/prepare-lighttpd-runtime.sh",
                {
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(verified_root / "source"),
                    "BUILD_ROOT": str(build_root),
                    "TMP_ROOT": str(verified_root / "tmp"),
                    "LOG_ROOT": str(verified_root / "logs"),
                    "LIGHTTPD_CONNECTOR_BUILD_ROOT": str(foreign_private_root),
                    "ALLOW_RUNTIME_BUILDS": "0",
                    "ALLOW_RUNTIME_DOWNLOADS": "0",
                },
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn(
                "lighttpd private build root must stay under",
                result.stdout + result.stderr,
            )

    def test_prepare_lighttpd_rejects_staged_source_outside_component_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            verified_root = temporary_root / "verified"
            component_cache = verified_root / "component-cache"
            staged_source = temporary_root / "untrusted-lighttpd-source"
            component_cache.mkdir(parents=True)
            staged_source.mkdir()
            result = self.run_script(
                ROOT / "ci/provisioning/prepare-lighttpd-runtime.sh",
                {
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(verified_root / "source"),
                    "BUILD_ROOT": str(verified_root / "build"),
                    "TMP_ROOT": str(verified_root / "tmp"),
                    "LOG_ROOT": str(verified_root / "logs"),
                    "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                    "LIGHTTPD_SOURCE_STAGE_DIR": str(staged_source),
                    "ALLOW_RUNTIME_BUILDS": "0",
                    "ALLOW_RUNTIME_DOWNLOADS": "0",
                },
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn(
                "LIGHTTPD_SOURCE_STAGE_DIR must stay under",
                result.stdout + result.stderr,
            )

            allowed_source = component_cache / "src" / "lighttpd-allowed"
            allowed_source.mkdir(parents=True)
            allowed_result = self.run_script(
                ROOT / "ci/provisioning/prepare-lighttpd-runtime.sh",
                {
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(verified_root / "source"),
                    "BUILD_ROOT": str(verified_root / "build"),
                    "TMP_ROOT": str(verified_root / "tmp"),
                    "LOG_ROOT": str(verified_root / "logs"),
                    "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                    "LIGHTTPD_SOURCE_STAGE_DIR": str(allowed_source),
                    "ALLOW_RUNTIME_BUILDS": "0",
                    "ALLOW_RUNTIME_DOWNLOADS": "0",
                },
            )
            self.assertEqual(allowed_result.returncode, 77, allowed_result.stdout + allowed_result.stderr)
            self.assertIn(
                "LIGHTTPD_SOURCE_STAGE_DIR must stay under",
                allowed_result.stdout + allowed_result.stderr,
            )

            traversal_source = verified_root / "untrusted-lighttpd-source"
            traversal_source.mkdir()
            traversal_result = self.run_script(
                ROOT / "ci/provisioning/prepare-lighttpd-runtime.sh",
                {
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(verified_root / "source"),
                    "BUILD_ROOT": str(verified_root / "build"),
                    "TMP_ROOT": str(verified_root / "tmp"),
                    "LOG_ROOT": str(verified_root / "logs"),
                    "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                    "LIGHTTPD_SOURCE_STAGE_DIR": str(
                        component_cache / "src" / ".." / ".." / "untrusted-lighttpd-source"
                    ),
                    "ALLOW_RUNTIME_BUILDS": "0",
                    "ALLOW_RUNTIME_DOWNLOADS": "0",
                },
            )
            self.assertEqual(traversal_result.returncode, 77, traversal_result.stdout + traversal_result.stderr)
            self.assertIn(
                "LIGHTTPD_SOURCE_STAGE_DIR contains traversal segments",
                traversal_result.stdout + traversal_result.stderr,
            )

    def test_prepare_lighttpd_does_not_execute_unverified_source_inside_component_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            verified_root = temporary_root / "verified"
            component_cache = verified_root / "component-cache"
            staged_source = component_cache / "src" / "lighttpd-unverified"
            marker = temporary_root / "unverified-configure-ran"
            staged_source.mkdir(parents=True)
            configure = staged_source / "configure"
            configure.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = \"--help\" ]; then exit 0; fi\n"
                "printf ran > \"$LIGHTTPD_UNVERIFIED_MARKER\"\n"
                "exit 0\n",
                encoding="utf-8",
            )
            configure.chmod(0o755)

            result = self.run_script(
                ROOT / "ci/provisioning/prepare-lighttpd-runtime.sh",
                {
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(verified_root / "source"),
                    "BUILD_ROOT": str(verified_root / "build"),
                    "TMP_ROOT": str(verified_root / "tmp"),
                    "LOG_ROOT": str(verified_root / "logs"),
                    "CONNECTOR_COMPONENT_CACHE": str(component_cache),
                    "LIGHTTPD_SOURCE_STAGE_DIR": str(staged_source),
                    "LIGHTTPD_UNVERIFIED_MARKER": str(marker),
                    "ALLOW_RUNTIME_BUILDS": "1",
                    "ALLOW_RUNTIME_DOWNLOADS": "0",
                },
            )

            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
            self.assertIn(
                "LIGHTTPD_SOURCE_STAGE_DIR must stay under",
                result.stdout + result.stderr,
            )

    def test_v3_api_smoke_rejects_injected_compiler_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "compiler-injection-ran"
            build_root = tmp_path / "build"
            result = self.run_script(
                ROOT / "ci/runtime/run-v3-api-smoke.sh",
                {
                    "BUILD_ROOT": str(build_root),
                    "CC": f"cc;touch {shlex.quote(str(marker))}",
                    "CXX": "c++",
                },
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertIn("compiler", result.stdout + result.stderr)
            self.assertFalse(marker.exists())

    def test_v3_api_smoke_rejects_make_function_path_inputs_before_make(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for variable in ("BUILD_ROOT", "BUILD_DIR", "MODSECURITY_V3_DIR"):
                with self.subTest(variable=variable):
                    marker = tmp_path / f"{variable.lower()}-make-eval-ran"
                    payload = f"/tmp/$(shell touch {marker})"
                    environment = {"CC": "cc", "CXX": "c++", variable: payload}
                    result = self.run_script(
                        ROOT / "ci/runtime/run-v3-api-smoke.sh", environment
                    )

                    self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                    self.assertIn("Make syntax", result.stdout + result.stderr)
                    self.assertFalse(marker.exists(), result.stdout + result.stderr)

    def test_v3_api_makefile_rejects_make_function_path_inputs_before_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for variable in ("BUILD_ROOT", "BUILD_DIR", "MODSECURITY_V3_DIR", "CC", "CXX"):
                with self.subTest(variable=variable):
                    marker = tmp_path / f"{variable.lower()}-direct-make-eval-ran"
                    payload = f"/tmp/$(shell touch {marker})"
                    result = subprocess.run(
                        [
                            "make",
                            "-C",
                            str(ROOT / "src/v3-api-smoke"),
                            "-n",
                            "check-prereqs",
                            f"{variable}={payload}",
                        ],
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )

                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("unsupported shell syntax", result.stdout + result.stderr)
                    self.assertFalse(marker.exists(), result.stdout + result.stderr)

            legitimate = subprocess.run(
                [
                    "make",
                    "-C",
                    str(ROOT / "src/v3-api-smoke"),
                    "-n",
                    "check-prereqs",
                    f"BUILD_ROOT={tmp_path / 'build'}",
                    f"BUILD_DIR={tmp_path / 'build' / 'v3-api-smoke'}",
                    f"MODSECURITY_V3_DIR={tmp_path / 'missing-v3'}",
                    "CC=cc",
                    "CXX=c++",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(legitimate.returncode, 0, legitimate.stdout + legitimate.stderr)
            self.assertNotIn(
                "unsupported Make variable syntax", legitimate.stdout + legitimate.stderr
            )

            for syntax, payload in (
                ("backtick", f"/tmp/`touch {tmp_path / 'backtick-ran'}`"),
                ("quote", f"/tmp/\";touch {tmp_path / 'quote-ran'};#"),
            ):
                with self.subTest(syntax=syntax):
                    result = subprocess.run(
                        [
                            "make",
                            "-C",
                            str(ROOT / "src/v3-api-smoke"),
                            "-n",
                            "check-prereqs",
                            f"BUILD_DIR={payload}",
                        ],
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("unsupported shell syntax", result.stdout + result.stderr)
                    self.assertFalse((tmp_path / f"{syntax}-ran").exists())

    def test_v3_api_makefile_ignores_caller_overrides_of_derived_containment_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "derived-override-eval-ran"
            payload = f"/tmp/$(shell touch {marker})"
            result = subprocess.run(
                [
                    "make",
                    "-C",
                    str(ROOT / "src/v3-api-smoke"),
                    "check-prereqs",
                    f"BUILD_DIR={ROOT / 'src/v3-api-smoke' / 'inside-checkout'}",
                    f"REPO_ROOT={payload}",
                    f"BUILD_DIR_ABS={payload}",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            # GNU Make reports a failing recipe as its own nonzero status
            # (normally 2), while the recipe itself exits 77.  The boundary
            # assertion is the fail-closed result and diagnostic, not Make's
            # wrapper exit-code translation.
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            output = result.stdout + result.stderr
            self.assertIn("blocked resolved BUILD_DIR is inside the checkout", output)
            self.assertIn(str(ROOT), output)
            self.assertFalse(marker.exists(), output)

            valid_root = tmp_path / "valid-build"
            legitimate = self.run_script(
                ROOT / "ci/runtime/run-v3-api-smoke.sh",
                {
                    "BUILD_ROOT": str(valid_root),
                    "BUILD_DIR": str(valid_root / "v3-api-smoke"),
                    "MODSECURITY_V3_DIR": str(valid_root / "ModSecurity_V3_build"),
                    "CC": "cc",
                    "CXX": "c++",
                },
            )
            self.assertNotIn("Make syntax", legitimate.stdout + legitimate.stderr)

    def test_v3_api_makefile_rejects_symlinked_build_path_into_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            linked_build = tmp_path / "linked-build"
            linked_build.symlink_to(ROOT, target_is_directory=True)
            result = subprocess.run(
                [
                    "make",
                    "-C",
                    str(ROOT / "src/v3-api-smoke"),
                    "check-prereqs",
                    f"BUILD_ROOT={tmp_path / 'build-root'}",
                    f"BUILD_DIR={linked_build / 'generated'}",
                    f"MODSECURITY_V3_DIR={tmp_path / 'missing-v3'}",
                    "CC=cc",
                    "CXX=c++",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("resolved BUILD_DIR is inside the checkout", result.stdout + result.stderr)
            self.assertFalse((ROOT / "generated").exists())

            valid_root = tmp_path / "valid-root"
            valid_build = valid_root / "v3-api-smoke"
            valid_v3 = tmp_path / "valid-v3"
            (valid_v3 / "headers/modsecurity").mkdir(parents=True)
            (valid_v3 / "headers/modsecurity/modsecurity.h").write_text("/* test */\n", encoding="utf-8")
            (valid_v3 / "src/.libs").mkdir(parents=True)
            (valid_v3 / "src/.libs/libmodsecurity.so").write_bytes(b"test")
            result = subprocess.run(
                [
                    "make",
                    "-C",
                    str(ROOT / "src/v3-api-smoke"),
                    "check-prereqs",
                    f"BUILD_ROOT={valid_root}",
                    f"BUILD_DIR={valid_build}",
                    f"MODSECURITY_V3_DIR={valid_v3}",
                    "CC=cc",
                    "CXX=c++",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(valid_build.exists(), "check-prereqs must not create the build directory")

    def test_nested_catalog_bootstrap_ignores_foreign_root_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-path-helper-sourced"
            foreign_ci = self.write_foreign_ci(tmp_path, marker, common_body=":\n")
            result = self.run_shell(
                "\n".join(
                    (
                        f"SCRIPT_DIR={shlex.quote(str(ROOT / 'ci/checks/catalog'))}",
                        f"CI_ROOT={shlex.quote(str(foreign_ci))}",
                        f"FRAMEWORK_ROOT={shlex.quote(str(tmp_path / 'foreign-framework'))}",
                        f". {shlex.quote(str(ROOT / 'ci/lib/path-bootstrap.sh'))}",
                        f"[ \"$CI_ROOT\" = {shlex.quote(str(ROOT / 'ci'))} ]",
                        f"[ \"$FRAMEWORK_ROOT\" = {shlex.quote(str(ROOT))} ]",
                    )
                ),
                {},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())

    def test_bootstrap_fails_closed_before_sourcing_a_foreign_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-path-helper-sourced"
            foreign_ci = self.write_foreign_ci(tmp_path, marker, common_body=":\n")
            invalid_script_dir = tmp_path / "not-a-framework" / "runtime"
            invalid_script_dir.mkdir(parents=True)
            result = self.run_shell(
                "\n".join(
                    (
                        f"SCRIPT_DIR={shlex.quote(str(invalid_script_dir))}",
                        f"CI_ROOT={shlex.quote(str(foreign_ci))}",
                        f"FRAMEWORK_ROOT={shlex.quote(str(tmp_path / 'foreign-framework'))}",
                        f". {shlex.quote(str(ROOT / 'ci/lib/path-bootstrap.sh'))}",
                    )
                ),
                {},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_runtime_entrypoint_ignores_foreign_ci_root_and_preserves_legitimate_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-runtime-helper-sourced"
            foreign_ci = self.write_foreign_ci(
                tmp_path,
                marker,
                common_body=(
                    f"touch {shlex.quote(str(marker))}\n"
                    "connector_smoke_run() { return 0; }\n"
                ),
            )
            verified_root = tmp_path / "verified"
            connector_root = tmp_path / "connector-root"
            harness = connector_root / "connectors/envoy/harness/run_envoy_smoke.sh"
            harness.parent.mkdir(parents=True)
            harness.write_text(
                "#!/bin/sh\nprintf '%s\\n' '{}' > \"$RESULTS_DIR/envoy-results.jsonl\"\n",
                encoding="utf-8",
            )
            harness.chmod(0o755)
            source_root = verified_root / "src"
            build_root = verified_root / "build"
            source_root.mkdir(parents=True)
            build_root.mkdir(parents=True)
            result = self.run_script(
                ROOT / "ci/runtime/run-envoy-smoke.sh",
                {
                    "CI_ROOT": str(foreign_ci),
                    "FRAMEWORK_ROOT": str(tmp_path / "foreign-framework"),
                    "CONNECTOR_ROOT": str(connector_root),
                    "VERIFIED_RUN_ROOT": str(verified_root),
                    "SOURCE_ROOT": str(source_root),
                    "BUILD_ROOT": str(build_root),
                    "TMP_ROOT": str(build_root / "tmp"),
                    "LOG_ROOT": str(build_root / "logs"),
                    "RESULTS_DIR": str(build_root / "results"),
                    "PYTHON": "sh",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertTrue((build_root / "results/envoy-results.jsonl").is_file())

    def test_provisioning_entrypoint_ignores_foreign_ci_root_and_finds_valid_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            marker = tmp_path / "foreign-provisioning-helper-sourced"
            foreign_ci = self.write_foreign_ci(
                tmp_path,
                marker,
                common_body=(
                    f"touch {shlex.quote(str(marker))}\n"
                    f"SOURCE_ROOT={shlex.quote(str(tmp_path / 'foreign-source'))}\n"
                ),
            )
            source = tmp_path / "modsecurity-source"
            source.mkdir()
            result = self.run_script(
                ROOT / "ci/provisioning/find-modsecurity-v3.sh",
                {
                    "CI_ROOT": str(foreign_ci),
                    "FRAMEWORK_ROOT": str(tmp_path / "foreign-framework"),
                    "CONNECTOR_ROOT": str(tmp_path / "connector-root"),
                    "SOURCE_ROOT": str(tmp_path / "source-root"),
                    "MODSECURITY_V3_SOURCE_DIR": str(source),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f"{source}\n")
            self.assertFalse(marker.exists())

    def test_starter_checks_reject_results_path_traversal_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            connector_root = root / "connector"
            (connector_root / "connectors").mkdir(parents=True)
            build_root = root / "build"
            escaped_root = root / "escaped"
            results_dir = build_root / "results" / ".." / ".." / "escaped"
            result = self.run_script(
                ROOT / "ci/runtime/run-connector-starter-checks.sh",
                {
                    "CONNECTOR_ROOT": str(connector_root),
                    "VERIFIED_RUN_ROOT": str(root / "verified"),
                    "SOURCE_ROOT": "/src",
                    "BUILD_ROOT": str(build_root),
                    "TMP_ROOT": str(build_root / "tmp"),
                    "LOG_ROOT": str(build_root / "logs"),
                    "RESULTS_DIR": str(results_dir),
                    "PYTHON": "/bin/true",
                },
            )
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertFalse(escaped_root.exists())

    def test_haproxy_runtime_rejects_a_shared_component_cache_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            verified = root / "verified"
            build_root = verified / "build"
            source_root = verified / "src"
            connector_root = root / "connector"
            cache_entry = (
                root
                / "cache"
                / "builds"
                / "connectors"
                / "haproxy"
                / ("a" * 64)
            )
            for directory in (
                build_root,
                source_root,
                connector_root,
                cache_entry / "haproxy-runtime-build",
                cache_entry / "haproxy-runtime" / "haproxy" / "sbin",
            ):
                directory.mkdir(parents=True, exist_ok=True)
            result = self.run_script(
                ROOT / "ci/provisioning/prepare-haproxy-runtime.sh",
                {
                    "CONNECTOR_ROOT": str(connector_root),
                    "VERIFIED_RUN_ROOT": str(verified),
                    "SOURCE_ROOT": str(source_root),
                    "BUILD_ROOT": str(build_root),
                    "TMP_ROOT": str(build_root / "tmp"),
                    "LOG_ROOT": str(build_root / "logs"),
                    "CONNECTOR_COMPONENT_CACHE": str(root / "cache"),
                    "HAPROXY_RUNTIME_BUILD_DIR": str(cache_entry / "haproxy-runtime-build"),
                    "HAPROXY_RUNTIME_BUILD_WORKTREE": str(
                        cache_entry / "haproxy-runtime-build" / "worktree"
                    ),
                    "HAPROXY_RUNTIME_DIR": str(cache_entry / "haproxy-runtime" / "haproxy"),
                    "HAPROXY_BIN": str(
                        cache_entry / "haproxy-runtime" / "haproxy" / "sbin" / "haproxy"
                    ),
                },
            )
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("HAPROXY_RUNTIME_BUILD_DIR must be under BUILD_ROOT", result.stdout)


if __name__ == "__main__":
    unittest.main()
