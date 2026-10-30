"""Execute the hosted provisioning-to-isolated-runtime environment boundary."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
WORKFLOW = source_path('.github/workflows/test-nginx-exact-head.yml', root=ROOT)


class NginxExactHeadRuntimeHandoffTest(unittest.TestCase):
    def setUp(self):
        candidate = Path(os.environ.get(
            "PARENT_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT)
        ))
        framework, error = trusted_framework_root(ROOT, candidate)
        if framework is None:
            self.skipTest(error)
        self.framework = framework
        job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["nginx-exact-head"]
        self.job_env = {key: str(value) for key, value in job["env"].items()}
        steps = {step.get("name"): step for step in job["steps"]}
        self.provision = steps["Provision pinned NGINX and connector runtime"]["run"]
        runtime = steps["Run isolated modsecurity_use_error_log on/off cells"]["run"]
        # Execute the checked-in env -i boundary and real wrapper, replacing
        # only the expensive/root-owned runtime fixture with an observer.
        self.runtime = runtime.split("/usr/bin/env -i", 1)[1].split(
            "/bin/sh -eu -s", 1
        )[0]
        self.runtime = "/usr/bin/env -i" + self.runtime + """/bin/sh -c '
        printf "%s|%s|%s" "$NGINX_BINARY" "$NGINX_MODULE" "${AMBIENT_SENTINEL-unset}"
        '
        """

    def run_handoff(self, *, snapshot_target="nginx", snapshot_cache=None, fail_prepare=False):
        with tempfile.TemporaryDirectory(prefix="nginx-runtime-handoff-") as temporary:
            root = Path(temporary)
            connector = root / "connector"
            for relative in (
                "ci/provisioning/cache/with-runtime-components.sh",
                "ci/tools/print-framework-apr-util-env.sh",
                "ci/runtime/lifecycle/reserve-runtime-env-snapshot.sh",
            ):
                destination = connector / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            (connector / "modules").mkdir()
            (connector / "modules/ModSecurity-test-Framework").symlink_to(self.framework)
            prepare = connector / "ci/provisioning/components/prepare-runtime-components.sh"
            prepare.parent.mkdir(parents=True)
            prepare.write_text('echo "unexpected second preparation" >&2\nexit 93\n')
            fake_bin = root / "bin"
            fake_bin.mkdir()
            make = fake_bin / "make"
            # Simulate only the external build boundary. The producer writes
            # the same invocation-local snapshot metadata as the provisioner.
            make.write_text("""#!/bin/sh
set -eu
[ "$1" = fetch-deps ] || exit 0
[ "${FAIL_PREPARE:-0}" != 1 ] || exit 94
snapshot=${RUNTIME_COMPONENT_ENV_SNAPSHOT:-$RUNTIME_REPORT_OUTPUT_ROOT/runtime-env-snapshot.uninherited.sh}
mkdir -p "$RUNTIME_REPORT_OUTPUT_ROOT"
cat > "$snapshot" <<EOF
export RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET='$TEST_SNAPSHOT_TARGET'
export RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE='$TEST_SNAPSHOT_CACHE'
export NGINX_BINARY='/prepared/nginx'
export NGINX_MODULE='/prepared/ngx_http_modsecurity_module.so'
EOF
""")
            make.chmod(0o700)
            run = root / "run"
            run.mkdir()
            output = run / "runtime-component-reports"
            github_env = root / "github-env"
            github_env.touch()
            cache = run / "component-cache"
            environment = {
                **self.job_env,
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "HOME": "/nonexistent",
                "GITHUB_WORKSPACE": str(connector),
                "GITHUB_ENV": str(github_env),
                "RUN_ROOT": str(run),
                "VERIFIED_RUN_ROOT": str(run),
                "BUILD_ROOT": str(run / "build"),
                "TMP_ROOT": str(run / "tmp"),
                "LOG_ROOT": str(run / "logs"),
                "RUNTIME_REPORT_OUTPUT_ROOT": str(output),
                "CONNECTOR_COMPONENT_CACHE": str(cache),
                "SOURCE_ROOT": str(run / "src"),
                "MODSECURITY_SOURCE_DIR": str(run / "src/ModSecurity_V3"),
                "MODSECURITY_V3_SOURCE_DIR": str(run / "src/ModSecurity_V3"),
                "NATIVE_FIXTURE_ROOT": str(root / "native-fixture"),
                "NGINX_FUNCTIONAL_A_PARENT_ROOT": str(root / "functional-parent"),
                "FUNCTIONAL_EVIDENCE_ROOT": str(run / "evidence"),
                "TEST_SNAPSHOT_TARGET": snapshot_target,
                "TEST_SNAPSHOT_CACHE": snapshot_cache or str(cache),
                "FAIL_PREPARE": "1" if fail_prepare else "0",
                "AMBIENT_SENTINEL": "must-not-leak",
            }
            result = subprocess.run(["/bin/sh", "-eu", "-c", self.provision],
                                    cwd=connector, env=environment, capture_output=True, text=True)
            published = github_env.read_text()
            if result.returncode:
                return result, published
            environment.update(line.split("=", 1) for line in published.splitlines())
            result = subprocess.run(["/bin/sh", "-eu", "-c", self.runtime],
                                    cwd=connector, env=environment, capture_output=True, text=True)
            return result, published

    def test_prepared_snapshot_crosses_clean_environment_without_a_second_prepare(self):
        result, published = self.run_handoff()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "/prepared/nginx|/prepared/ngx_http_modsecurity_module.so|unset")
        self.assertIn("RUNTIME_COMPONENT_ENV_SNAPSHOT=", published)

    def test_snapshot_target_and_cache_checks_still_fail_closed(self):
        for arguments, message in (
            ({"snapshot_target": "apache"}, "snapshot target mismatch"),
            ({"snapshot_cache": "/different/cache"}, "snapshot cache mismatch"),
        ):
            with self.subTest(arguments=arguments):
                result, _ = self.run_handoff(**arguments)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertNotIn("unexpected second preparation", result.stderr)

    def test_failed_provisioning_does_not_publish_a_snapshot(self):
        result, published = self.run_handoff(fail_prepare=True)
        self.assertEqual(result.returncode, 94, result.stdout + result.stderr)
        self.assertEqual(published, "")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
