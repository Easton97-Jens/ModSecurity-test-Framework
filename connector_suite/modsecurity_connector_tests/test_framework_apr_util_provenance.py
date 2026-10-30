from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
BRIDGE = source_path('ci/tools/print-framework-apr-util-env.sh', root=ROOT)
PREPARE = source_path('ci/provisioning/components/prepare-runtime-components.sh', root=ROOT)
WITH_RUNTIME = source_path('ci/provisioning/cache/with-runtime-components.sh', root=ROOT)
FRAMEWORK_ROOT = Path(
    os.environ.get("PARENT_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT))
)

components = load_source(source_path('ci/provisioning/components/prepare-runtime-components.py', root=ROOT))


def apr_key(suffix: str) -> str:
    return "APR_UTIL_" + suffix


APR_KEYS = {suffix: apr_key(suffix) for suffix in ("VERSION", "SOURCE_URL", "SHA256", "SHA256_URL")}


class FrameworkAprUtilProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        self.framework_root = framework_root

    def require_current_framework(self) -> Path:
        return self.framework_root

    @staticmethod
    def fixture_tuple(version: str, digest: str) -> dict[str, str]:
        source_url = f"https://downloads.apache.org/apr/apr-util-{version}.tar.bz2"
        return {
            APR_KEYS["VERSION"]: version,
            APR_KEYS["SOURCE_URL"]: source_url,
            APR_KEYS["SHA256"]: digest,
            APR_KEYS["SHA256_URL"]: f"{source_url}.sha256",
        }

    @staticmethod
    def clean_environment() -> dict[str, str]:
        environment = os.environ.copy()
        for key in (*components.FRAMEWORK_APR_UTIL_ENV_KEYS, "ENV", "BASH_ENV", "SHELLOPTS"):
            environment.pop(key, None)
        return environment

    def bridge(
        self,
        framework_root: Path,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", str(BRIDGE), str(framework_root), str(ROOT)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def canonical_tuple(self) -> dict[str, str]:
        result = self.bridge(self.require_current_framework(), self.clean_environment())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 4)
        values, error = components._guarded_apr_util_tuple(result.stdout.encode("utf-8"))
        self.assertIsNone(error)
        self.assertIsNotNone(values)
        assert values is not None
        self.assertEqual(set(values), set(components.FRAMEWORK_APR_UTIL_ENV_KEYS))
        return values

    @staticmethod
    def write_fixture_common(common_sh: Path, tuple_values: dict[str, str], extra_lines: tuple[str, ...] = ()) -> None:
        common_sh.parent.mkdir(parents=True)
        assignments = tuple(
            f"{key}={components.sh_quote(value)}"
            for key, value in tuple_values.items()
        )
        common_sh.write_text(
            "\n".join(
                (
                    "#!/bin/sh",
                    *assignments,
                    *extra_lines,
                    "ci_require_apr_util_pinned_provenance() { :; }",
                    "ci_validate_https_runtime_url_config() { :; }",
                )
            )
            + "\n",
            encoding="utf-8",
        )

    def test_bridge_allows_absent_and_full_canonical_tuple(self) -> None:
        canonical = self.canonical_tuple()
        inherited = self.clean_environment()
        inherited.update(canonical)
        result = self.bridge(self.framework_root, inherited)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            self.bridge(self.framework_root, self.clean_environment()).stdout,
        )

    def test_bridge_rejects_partial_and_empty_tuples(self) -> None:
        canonical = self.canonical_tuple()
        ordered_keys = tuple(components.FRAMEWORK_APR_UTIL_ENV_KEYS)
        for key in ordered_keys:
            with self.subTest(partial=key):
                environment = self.clean_environment()
                environment[key] = canonical[key]
                result = self.bridge(self.framework_root, environment)
                self.assertEqual(result.returncode, 77)
                self.assertEqual(result.stdout, "")
        for size in (2, 3):
            with self.subTest(partial_size=size):
                environment = self.clean_environment()
                environment.update({key: canonical[key] for key in ordered_keys[:size]})
                result = self.bridge(self.framework_root, environment)
                self.assertEqual(result.returncode, 77)
        for key in ordered_keys:
            with self.subTest(empty=key):
                environment = self.clean_environment()
                environment[key] = ""
                result = self.bridge(self.framework_root, environment)
                self.assertEqual(result.returncode, 77)
                self.assertEqual(result.stdout, "")

    def test_bridge_rejects_each_mismatch_and_a_coherent_alternative(self) -> None:
        canonical = self.canonical_tuple()
        mismatch_version = "9.9.8"
        mirror_source = f"https://mirror.invalid/apr-util-{mismatch_version}.tar.bz2"
        replacements = {
            APR_KEYS["VERSION"]: mismatch_version,
            APR_KEYS["SOURCE_URL"]: mirror_source,
            APR_KEYS["SHA256"]: "b" * 64,
            APR_KEYS["SHA256_URL"]: f"{mirror_source}.sha256",
        }
        for key, replacement in replacements.items():
            with self.subTest(mismatch=key):
                environment = self.clean_environment()
                environment.update(canonical)
                environment[key] = replacement
                result = self.bridge(self.framework_root, environment)
                self.assertEqual(result.returncode, 77)
                self.assertEqual(result.stdout, "")
        alternative = self.clean_environment()
        alternative.update(self.fixture_tuple("9.9.9", "a" * 64))
        result = self.bridge(self.framework_root, alternative)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stdout, "")

    def test_framework_repeated_sourcing_preserves_the_canonical_tuple(self) -> None:
        self.require_current_framework()
        script = (
            '. "$1/ci/lib/common.sh"; ci_require_apr_util_pinned_provenance; '
            'first="$APR_UTIL_VERSION:$APR_UTIL_SOURCE_URL:$APR_UTIL_SHA256:$APR_UTIL_SHA256_URL"; '
            '. "$1/ci/lib/common.sh"; ci_require_apr_util_pinned_provenance; '
            'second="$APR_UTIL_VERSION:$APR_UTIL_SOURCE_URL:$APR_UTIL_SHA256:$APR_UTIL_SHA256_URL"; '
            'test "$first" = "$second"'
        )
        result = subprocess.run(
            ["/bin/sh", "-eu", "-c", script, "framework-child-source", str(self.framework_root)],
            cwd=ROOT,
            env=self.clean_environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_framework_guard_rejects_a_post_source_tuple_mutation(self) -> None:
        self.require_current_framework()
        version_key = APR_KEYS["VERSION"]
        script = (
            '. "$1/ci/lib/common.sh"; ci_require_apr_util_pinned_provenance; '
            f'{version_key}=9.9.9; ci_require_apr_util_pinned_provenance'
        )
        result = subprocess.run(
            ["/bin/sh", "-eu", "-c", script, "framework-post-source-mutation", str(self.framework_root)],
            cwd=ROOT,
            env=self.clean_environment(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 77, result.stderr)

    def test_framework_guard_environment_removes_tuple_startup_hooks_and_internal_snapshots(self) -> None:
        base = self.fixture_tuple("7.8.9", "a" * 64)
        base.update(
            {
                "ENV": "hook",
                "BASH_ENV": "hook",
                "SHELLOPTS": "nounset",
                "PATH": "/unsafe",
                "CI_INHERITED_UPSTREAM_ENV": "ENVOY_VERSION=1.39.0",
                "CI_INHERITED_UPSTREAM_ENV_STATUS": "0",
            }
        )
        guarded = components._framework_guard_environment(base, ROOT, FRAMEWORK_ROOT)
        for key in (
            *components.FRAMEWORK_APR_UTIL_ENV_KEYS,
            *components.FRAMEWORK_TRANSIENT_ENV_KEYS,
            "ENV",
            "BASH_ENV",
            "SHELLOPTS",
        ):
            self.assertNotIn(key, guarded)
        self.assertEqual(guarded["PATH"], components._TRUSTED_FRAMEWORK_GUARD_PATH)

    def test_python_loader_accepts_only_canonical_propagation(self) -> None:
        canonical = self.canonical_tuple()
        absent = self.clean_environment()
        loaded, status = components.load_framework_environment(ROOT, self.framework_root, absent)
        self.assertEqual(status, "loaded")
        self.assertEqual({key: loaded[key] for key in canonical}, canonical)
        self.assertFalse(set(components.FRAMEWORK_TRANSIENT_ENV_KEYS) & set(loaded))

        inherited = self.clean_environment()
        inherited.update(canonical)
        loaded, status = components.load_framework_environment(ROOT, self.framework_root, inherited)
        self.assertEqual(status, "loaded")
        self.assertEqual({key: loaded[key] for key in canonical}, canonical)
        inherited[APR_KEYS["VERSION"]] = "9.9.8"
        self.assertEqual(loaded[APR_KEYS["VERSION"]], canonical[APR_KEYS["VERSION"]])

    def test_python_loader_removes_nested_framework_snapshot_before_a_resourced_common_sh(self) -> None:
        nested = self.clean_environment()
        nested.update(
            {
                "ENVOY_VERSION": "1.39.1",
                "CI_INHERITED_UPSTREAM_ENV": "ENVOY_VERSION=1.39.1",
                "CI_INHERITED_UPSTREAM_ENV_STATUS": "0",
            }
        )
        loaded, status = components.load_framework_environment(ROOT, self.framework_root, nested)
        self.assertEqual(status, "loaded")
        self.assertEqual(loaded["ENVOY_VERSION"], "1.39.1")
        for key in components.FRAMEWORK_TRANSIENT_ENV_KEYS:
            self.assertNotIn(key, loaded)

    def test_python_loader_rejects_partial_empty_mismatch_and_alternative_tuples(self) -> None:
        canonical = self.canonical_tuple()
        partial = self.clean_environment()
        partial[APR_KEYS["VERSION"]] = canonical[APR_KEYS["VERSION"]]
        loaded, status = components.load_framework_environment(ROOT, self.framework_root, partial)
        self.assertEqual(loaded, partial)
        self.assertTrue(status.startswith("failed:inherited_parent_apr_util_partial:"), status)

        empty = self.clean_environment()
        empty.update(canonical)
        empty[APR_KEYS["SHA256"]] = ""
        loaded, status = components.load_framework_environment(ROOT, self.framework_root, empty)
        self.assertEqual(loaded, empty)
        self.assertIn("inherited_parent_apr_util_empty", status)

        mismatch = self.clean_environment()
        mismatch.update(canonical)
        mismatch_version = "9.9.8"
        mismatch[APR_KEYS["SOURCE_URL"]] = f"https://mirror.invalid/apr-util-{mismatch_version}.tar.bz2"
        loaded, status = components.load_framework_environment(ROOT, self.framework_root, mismatch)
        self.assertEqual(loaded, mismatch)
        self.assertEqual(status, "failed:inherited_parent_apr_util_mismatch")

        alternative = self.clean_environment()
        alternative.update(self.fixture_tuple("9.9.9", "a" * 64))
        loaded, status = components.load_framework_environment(ROOT, self.framework_root, alternative)
        self.assertEqual(loaded, alternative)
        self.assertEqual(status, "failed:inherited_parent_apr_util_mismatch")

    def test_loader_scrubs_startup_hooks_and_rejects_bridge_errors(self) -> None:
        tuple_values = self.fixture_tuple("7.8.9", "a" * 64)
        with tempfile.TemporaryDirectory(prefix="framework-apr-util-loader-") as temporary:
            framework_root = Path(temporary) / "framework"
            common_sh = framework_root / "ci" / "lib" / "common.sh"
            self.write_fixture_common(
                common_sh,
                tuple_values,
                (
                    "[ -z \"${ENV+x}\" ] || exit 77",
                    "[ -z \"${BASH_ENV+x}\" ] || exit 77",
                    "[ -z \"${SHELLOPTS+x}\" ] || exit 77",
                    "COMMON_CONTROL=passed",
                ),
            )
            environment = self.clean_environment()
            environment.update({"ENV": "untrusted-hook", "BASH_ENV": "untrusted-hook", "SHELLOPTS": "nounset"})
            loaded, status = components.load_framework_environment(ROOT, framework_root, environment)
            self.assertEqual(status, "loaded")
            self.assertEqual({key: loaded[key] for key in tuple_values}, tuple_values)
            self.assertEqual(loaded["COMMON_CONTROL"], "passed")
            self.assertNotIn("ENV", loaded)
            self.assertNotIn("BASH_ENV", loaded)
            self.assertNotIn("SHELLOPTS", loaded)

            with mock.patch.object(components, "_run_framework_guard", return_value=(None, "failed:bridge-test")) as run_guard:
                rejected, rejected_status = components.load_framework_environment(ROOT, framework_root, environment)
            self.assertEqual(rejected, environment)
            self.assertEqual(rejected_status, "failed:bridge-test")
            run_guard.assert_called_once()

    def test_loader_rejects_bridge_common_mismatch_and_timeout(self) -> None:
        tuple_values = self.fixture_tuple("7.8.9", "a" * 64)
        mismatch = dict(tuple_values)
        mismatch[APR_KEYS["SHA256"]] = "b" * 64
        bridge_output = "".join(
            f"{key}={components.sh_quote(value)}\n" for key, value in tuple_values.items()
        ).encode("utf-8")
        common_output = b"".join(
            f"{key}={value}".encode("utf-8") + b"\0" for key, value in mismatch.items()
        )
        with tempfile.TemporaryDirectory(prefix="framework-apr-util-mismatch-") as temporary:
            framework_root = Path(temporary) / "framework"
            common_sh = framework_root / "ci" / "lib" / "common.sh"
            common_sh.parent.mkdir(parents=True)
            common_sh.write_text("#!/bin/sh\n", encoding="utf-8")
            environment = self.clean_environment()
            with mock.patch.object(
                components,
                "_run_framework_guard",
                side_effect=((bridge_output, None), (common_output, None)),
            ):
                loaded, status = components.load_framework_environment(ROOT, framework_root, environment)
            self.assertEqual(loaded, environment)
            self.assertEqual(status, "failed:framework_apr_util_guarded_tuple_mismatch")

        with mock.patch.object(
            components.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["/bin/sh"], 60),
        ):
            output, status = components._run_framework_guard(["/bin/sh"], ROOT, {})
        self.assertIsNone(output)
        self.assertTrue(status is not None and status.startswith("failed:timeout loading common.sh"), status)

    def test_malformed_apr_util_tuples_fail_closed(self) -> None:
        valid = self.fixture_tuple("7.8.9", "a" * 64)
        self.assertEqual(components.require_apr_util_pinned_provenance(valid), valid)
        malformed_version = "7.8.9"
        mirror_source = f"https://mirror.invalid/apr-util-{malformed_version}.tar.bz2"
        wrong_archive = f"https://downloads.apache.org/apr/apr-util-{malformed_version}.tar.gz"
        malformed_values = (
            (APR_KEYS["SOURCE_URL"], mirror_source),
            (APR_KEYS["SOURCE_URL"], wrong_archive),
            (APR_KEYS["SHA256_URL"], "https://downloads.apache.org/apr/foreign.sha256"),
            (APR_KEYS["SHA256"], "not-a-sha256"),
        )
        for key, value in malformed_values:
            with self.subTest(malformed=key):
                candidate = dict(valid)
                candidate[key] = value
                with self.assertRaises(RuntimeError):
                    components.require_apr_util_pinned_provenance(candidate)

    def test_apr_util_version_rejects_unicode_digits(self) -> None:
        unicode_version = "١.٢.٣"
        candidate = self.fixture_tuple(unicode_version, "a" * 64)
        self.assertIsNone(components.APR_UTIL_VERSION_RE.fullmatch(unicode_version))
        with self.assertRaises(RuntimeError):
            components.require_apr_util_pinned_provenance(candidate)

    def test_apr_util_cache_identity_changes_for_version_and_sha(self) -> None:
        first = self.fixture_tuple("7.8.9", "a" * 64)
        second = self.fixture_tuple("7.8.10", "a" * 64)
        changed_sha = dict(first)
        changed_sha[APR_KEYS["SHA256"]] = "b" * 64
        first_identity = components.apr_util_archive_cache_identity(first)
        self.assertNotEqual(first_identity["cache_key"], components.apr_util_archive_cache_identity(second)["cache_key"])
        self.assertNotEqual(first_identity["cache_key"], components.apr_util_archive_cache_identity(changed_sha)["cache_key"])
        self.assertEqual(first_identity["archive_name"], f"apr-util-{first[APR_KEYS['VERSION']]}.tar.bz2")

    def launcher_environment(self, temporary: Path) -> tuple[dict[str, str], Path, Path]:
        marker = temporary / "python-invoked"
        network_marker = temporary / "unexpected-network-command"
        invalid_snapshot = temporary / "outside" / "runtime-env.sh"
        site_root = temporary / "site"
        site_root.mkdir()
        (site_root / "sitecustomize.py").write_text(
            "\n".join(
                (
                    "import os",
                    "import sys",
                    "from pathlib import Path",
                    "Path(os.environ['APR_UTIL_TEST_PYTHON_MARKER']).write_text('invoked', encoding='utf-8')",
                    "sys.argv.extend(('--runtime-env-snapshot', os.environ['APR_UTIL_TEST_INVALID_SNAPSHOT']))",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        fake_bin = temporary / "fake-bin"
        fake_bin.mkdir()
        for command in ("curl", "git", "tar", "sha256sum"):
            path = fake_bin / command
            path.write_text(
                "#!/bin/sh\nprintf '%s' \"$0\" > \"$APR_UTIL_TEST_NETWORK_MARKER\"\nexit 99\n",
                encoding="utf-8",
            )
            path.chmod(0o755)
        run_root = temporary / "run"
        environment = self.clean_environment()
        environment.update(
            {
                "CONNECTOR_ROOT": str(ROOT),
                "FRAMEWORK_ROOT": str(self.framework_root),
                "PYTHON": sys.executable,
                "PYTHONPATH": str(site_root),
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "RUNNER_TEMP": str(temporary),
                "VERIFIED_RUN_ROOT": str(run_root),
                "VERIFIED_BUILD_ROOT": str(run_root / "build"),
                "VERIFIED_TMP_ROOT": str(run_root / "tmp"),
                "VERIFIED_LOG_ROOT": str(run_root / "logs"),
                "CACHE_ROOT": str(run_root / "cache-v2"),
                "VERIFIED_COMPONENT_CACHE": str(run_root / "cache-v2" / "shared"),
                "CONNECTOR_COMPONENT_CACHE": str(run_root / "cache-v2" / "shared"),
                "RUNTIME_REPORT_OUTPUT_ROOT": str(run_root / "reports"),
                "BUILD_ROOT": str(run_root / "build"),
                "TMP_ROOT": str(run_root / "tmp"),
                "LOG_ROOT": str(run_root / "logs"),
                "MRTS_NATIVE_ROOT": str(run_root / "native"),
                "APR_UTIL_TEST_PYTHON_MARKER": str(marker),
                "APR_UTIL_TEST_NETWORK_MARKER": str(network_marker),
                "APR_UTIL_TEST_INVALID_SNAPSHOT": str(invalid_snapshot),
            }
        )
        return environment, marker, network_marker

    def test_real_shell_to_python_transition_accepts_framework_tuple_before_containment_stop(self) -> None:
        self.require_current_framework()
        with tempfile.TemporaryDirectory(prefix="framework-apr-util-shell-python-") as temporary:
            environment, marker, network_marker = self.launcher_environment(Path(temporary))
            result = subprocess.run(
                ["/bin/sh", str(PREPARE)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            marker_exists = marker.is_file()
            network_command_ran = network_marker.exists()
        combined_output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 77, combined_output)
        self.assertTrue(marker_exists)
        self.assertFalse(network_command_ran)
        self.assertIn("runtime_env_snapshot_outside_output_root", combined_output)
        self.assertNotIn("inherited_parent_apr_util", combined_output)

    def test_with_runtime_components_passes_canonical_tuple_to_child_and_blocks_mutation(self) -> None:
        canonical = self.canonical_tuple()
        with tempfile.TemporaryDirectory(prefix="framework-apr-util-parent-child-") as temporary:
            environment, marker, network_marker = self.launcher_environment(Path(temporary))
            result = subprocess.run(
                ["/bin/sh", str(WITH_RUNTIME)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            combined_output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 77, combined_output)
            self.assertTrue(marker.is_file())
            self.assertFalse(network_marker.exists())
            self.assertIn("runtime_env_snapshot_outside_output_root", combined_output)
            self.assertNotIn("inherited_parent_apr_util", combined_output)

        version_only_mismatch = dict(canonical)
        version_only_mismatch[APR_KEYS["VERSION"]] = "9.9.9"
        mutations: tuple[tuple[str, dict[str, str]], ...] = (
            ("partial-version", {APR_KEYS["VERSION"]: canonical[APR_KEYS["VERSION"]]}),
            ("version-only-mismatch", version_only_mismatch),
            ("complete-alternative", self.fixture_tuple("9.9.9", "a" * 64)),
            ("empty-member", {APR_KEYS["SHA256"]: ""}),
        )
        for label, values in mutations:
            with self.subTest(mutation=label), tempfile.TemporaryDirectory(
                prefix="framework-apr-util-parent-child-mutation-"
            ) as temporary:
                environment, marker, network_marker = self.launcher_environment(Path(temporary))
                environment.update(values)
                result = subprocess.run(
                    ["/bin/sh", str(WITH_RUNTIME)],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertFalse(marker.exists())
                self.assertFalse(network_marker.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
