"""Mode-level regression coverage for the hosted NGINX worker path layout."""

from __future__ import annotations

from pathlib import Path
import stat
import tempfile
import unittest


class NginxFunctionalWorkerTraversalLayoutTest(unittest.TestCase):
    @staticmethod
    def make_directory(path: Path, mode: int) -> None:
        path.mkdir(parents=True)
        path.chmod(mode)

    def assert_non_enumerable_worker_ancestor(self, path: Path) -> None:
        self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o711, path)

    def assert_private_leaf(self, path: Path) -> None:
        self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o700, path)

    def test_dedicated_functional_tree_exposes_only_required_ancestor_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nginx-functional-worker-layout-") as temporary:
            root = Path(temporary)
            job_root = root / "ModSecurity-conector-nginx-functional-root.fixture123"
            run_root = job_root / "ModSecurity-conector-nginx-exact-head"
            functional_parent = job_root / "ModSecurity-conector-nginx-functional-parent"
            functional_root = functional_parent / "nginx-hosted-functional-a"
            mode_root = functional_root / "on"
            case_root = mode_root / "phase4"
            runtime_root = case_root / "runtime"
            config_root = runtime_root / "conf"
            log_root = case_root / "logs"
            harness_root = case_root / "harness"
            worker_state = harness_root / "worker-state"
            server_logs = harness_root / "server-logs"

            self.make_directory(job_root, 0o711)
            self.make_directory(run_root, 0o700)
            self.make_directory(functional_parent, 0o711)
            self.make_directory(functional_root, 0o711)
            self.make_directory(mode_root, 0o711)
            self.make_directory(case_root, 0o711)
            self.make_directory(runtime_root, 0o711)
            self.make_directory(config_root, 0o700)
            self.make_directory(log_root, 0o700)
            self.make_directory(harness_root, 0o711)
            self.make_directory(worker_state, 0o700)
            self.make_directory(server_logs, 0o700)

            self.assert_private_leaf(run_root)
            self.assertEqual(run_root.parent, job_root)
            self.assertEqual(functional_parent.parent, job_root)
            self.assertNotEqual(functional_parent, run_root)
            for ancestor in (
                job_root,
                functional_parent,
                functional_root,
                mode_root,
                case_root,
                runtime_root,
                harness_root,
            ):
                self.assert_non_enumerable_worker_ancestor(ancestor)
            for private_leaf in (config_root, log_root, worker_state, server_logs):
                self.assert_private_leaf(private_leaf)
            with self.assertRaises(ValueError):
                functional_parent.relative_to(run_root)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
