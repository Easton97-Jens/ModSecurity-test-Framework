from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
RESOLVER_PATH = source_path('ci/runtime/common/resolve-runtime-paths.py', root=ROOT)
resolver = load_source(RESOLVER_PATH)


class ResolveRuntimePathsTest(unittest.TestCase):
    def resolve(self, root: Path, connector: str = "traefik", run_id: str = "run-20260711") -> resolver.RuntimePaths:
        return resolver.resolve_runtime_paths(
            connector=connector,
            run_id=run_id,
            invocation_root=root,
            evidence_root=root / "evidence",
            build_root=root / "build",
            run_root=root / "runs",
            log_root=root / "logs",
            cache_root=root / "cache",
        )

    def test_resolves_distinct_connector_scoped_roots_and_shared_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            paths = self.resolve(root)

            self.assertEqual(root / "evidence/traefik/run-20260711", paths.evidence_run_root)
            self.assertEqual(root / "build/traefik/run-20260711", paths.connector_build_root)
            self.assertEqual(root / "runs/traefik/run-20260711", paths.connector_run_root)
            self.assertEqual(root / "logs/traefik/run-20260711", paths.connector_log_root)
            self.assertEqual(root / "cache/shared", paths.shared_component_cache)
            self.assertEqual(root, paths.invocation_root)
            self.assertEqual(
                set(paths.shell_values()),
                {
                    "EVIDENCE_RUN_ROOT",
                    "CONNECTOR_BUILD_ROOT",
                    "CONNECTOR_RUN_ROOT",
                    "CONNECTOR_LOG_ROOT",
                    "SHARED_COMPONENT_CACHE",
                },
            )
            outputs = (
                paths.evidence_run_root,
                paths.connector_build_root,
                paths.connector_run_root,
                paths.connector_log_root,
                paths.shared_component_cache,
            )
            for index, left in enumerate(outputs):
                for right in outputs[index + 1 :]:
                    self.assertFalse(resolver.roots_overlap(left, right))

    def test_same_run_id_keeps_connector_builds_isolated_but_shares_components(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            apache = self.resolve(root, connector="apache", run_id="same-run")
            traefik = self.resolve(root, connector="traefik", run_id="same-run")

            self.assertNotEqual(apache.connector_build_root, traefik.connector_build_root)
            self.assertNotEqual(apache.connector_run_root, traefik.connector_run_root)
            self.assertEqual(apache.shared_component_cache, traefik.shared_component_cache)

    def test_normalizes_safe_relative_bases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            paths = resolver.resolve_runtime_paths(
                connector="envoy",
                run_id="relative-run",
                invocation_root=root,
                evidence_root="evidence/./canonical",
                build_root="build",
                run_root="runs",
                log_root="logs",
                cache_root="cache",
                cwd=root,
            )

            self.assertEqual(root / "evidence/canonical/envoy/relative-run", paths.evidence_run_root)
            self.assertTrue(paths.connector_build_root.is_absolute())
            self.assertEqual(root / "cache/shared", paths.shared_component_cache)

    def test_rejects_empty_invalid_and_traversal_identifiers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            kwargs = {
                "run_id": "valid-run",
                "invocation_root": root,
                "evidence_root": root / "evidence",
                "build_root": root / "build",
                "run_root": root / "runs",
                "log_root": root / "logs",
                "cache_root": root / "cache",
            }
            for connector in ("", "Apache", "unknown", "../traefik"):
                with self.subTest(connector=connector):
                    with self.assertRaises(resolver.RuntimePathError):
                        resolver.resolve_runtime_paths(connector=connector, **kwargs)
            kwargs_without_run_id = {
                key: value for key, value in kwargs.items() if key != "run_id"
            }
            for run_id in ("", "../escape", "run/escape", "run..escape", "-bad"):
                with self.subTest(run_id=run_id):
                    with self.assertRaises(resolver.RuntimePathError):
                        resolver.resolve_runtime_paths(
                            connector="traefik", run_id=run_id, **kwargs_without_run_id
                        )

    def test_rejects_base_traversal_foreign_connector_and_overlaps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            common = {
                "connector": "traefik",
                "run_id": "run-1",
                "invocation_root": root,
                "evidence_root": root / "evidence",
                "build_root": root / "build",
                "run_root": root / "runs",
                "log_root": root / "logs",
                "cache_root": root / "cache",
            }
            with self.assertRaisesRegex(resolver.RuntimePathError, "traversal"):
                resolver.resolve_runtime_paths(**{**common, "build_root": "build/../escape"}, cwd=root)
            with self.assertRaisesRegex(resolver.RuntimePathError, "foreign connector"):
                resolver.resolve_runtime_paths(**{**common, "build_root": root / "apache-build"})
            with self.assertRaisesRegex(resolver.RuntimePathError, "root overlap"):
                resolver.resolve_runtime_paths(**{**common, "log_root": root / "runs"})
            with self.assertRaisesRegex(resolver.RuntimePathError, "root overlap"):
                resolver.resolve_runtime_paths(**{**common, "cache_root": root / "build/cache"})

    def test_rejects_broad_system_and_symlink_base_escapes(self) -> None:
        """Writable lifecycle bases cannot resolve to broad or system-owned locations."""
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            common = {
                "connector": "traefik",
                "run_id": "run-escape",
                "invocation_root": root,
                "evidence_root": root / "evidence",
                "build_root": root / "build",
                "run_root": root / "runs",
                "log_root": root / "logs",
                "cache_root": root / "cache",
            }
            for escaped_base in {
                Path("/"),
                Path("/tmp"),
                Path("/var"),
                Path("/var/tmp"),
                Path("/etc/evidence-escape"),
                Path("/root/evidence-escape"),
            }:
                with self.subTest(escaped_base=escaped_base):
                    escaped_request = {**common, "build_root": escaped_base}
                    with self.assertRaises(resolver.RuntimePathError):
                        resolver.resolve_runtime_paths(**escaped_request)

            unsafe_invocation = {**common, "invocation_root": Path("/runtime-escape")}
            with self.assertRaises(resolver.RuntimePathError):
                resolver.resolve_runtime_paths(**unsafe_invocation)

            root_link = root / "root-link"
            root_link.symlink_to("/root", target_is_directory=True)
            with self.assertRaises(resolver.RuntimePathError):
                resolver.resolve_runtime_paths(**{**common, "build_root": root_link / "evidence-escape"})

    def test_rejects_safe_base_outside_validated_invocation_root(self) -> None:
        """A safe-looking sibling directory cannot escape the selected run root."""
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            outside = root.parent / "outside-invocation"
            common = {
                "connector": "traefik",
                "run_id": "run-escape",
                "invocation_root": root,
                "evidence_root": root / "evidence",
                "build_root": root / "build",
                "run_root": root / "runs",
                "log_root": root / "logs",
                "cache_root": root / "cache",
            }
            with self.assertRaisesRegex(resolver.RuntimePathError, "inside invocation_root"):
                resolver.resolve_runtime_paths(**{**common, "build_root": outside / "build"})

    def test_cli_emits_json_and_shell_assignments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-resolver-") as temporary:
            root = Path(temporary)
            arguments = [
                "--connector", "traefik",
                "--run-id", "cli-run",
                "--invocation-root", str(root),
                "--evidence-root", str(root / "evidence"),
                "--build-root", str(root / "build"),
                "--run-root", str(root / "runs"),
                "--log-root", str(root / "logs"),
                "--cache-root", str(root / "cache"),
            ]
            json_result = subprocess.run(
                [sys.executable, str(RESOLVER_PATH), *arguments],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(json_result.returncode, 0, json_result.stderr)
            payload = json.loads(json_result.stdout)
            self.assertEqual(payload["connector"], "traefik")
            self.assertEqual(str(root / "build/traefik/cli-run"), payload["build_root"])
            self.assertEqual(str(root / "cache/shared"), payload["shared_component_cache"])

            shell_result = subprocess.run(
                [sys.executable, str(RESOLVER_PATH), *arguments, "--format", "shell"],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(shell_result.returncode, 0, shell_result.stderr)
            self.assertIn("export EVIDENCE_RUN_ROOT=", shell_result.stdout)
            self.assertIn("export SHARED_COMPONENT_CACHE=", shell_result.stdout)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
