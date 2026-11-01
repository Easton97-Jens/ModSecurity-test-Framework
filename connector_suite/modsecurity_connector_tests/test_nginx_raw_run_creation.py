"""Execute the lifecycle's real directory boundary under a restrictive umask."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = connector_root()
BASELINE = source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)


class RawRunCreationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw_parent = self.root / "runs/nginx"
        self.raw_parent.mkdir(parents=True)
        self.raw = self.raw_parent / "fresh-run"
        self.logs = self.root / "logs/nginx/fresh-run"
        self.canonical = self.root / "canonical/nginx/fresh-run"
        source = BASELINE.read_text(encoding="utf-8")
        self.block = source[source.index("reject_symlink_components() {"):source.index("# Reserve one exact local runtime-env destination")]

    def run_boundary(self, connector="nginx", profile="full_lifecycle", raw=None, prefix=""):
        env = dict(os.environ, connector=connector, NO_CRS_ARTIFACT_PROFILE=profile,
                   CONNECTOR_ROOT=str(ROOT), RAW_DIR=str(raw or self.raw),
                   RUN_DIR=str(self.canonical), LOG_DIR=str(self.logs),
                   RESULTS_DIR=str((raw or self.raw) / "results"),
                   NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR="")
        return subprocess.run(["sh", "-eu", "-c", "umask 077\n" + prefix + self.block],
                              env=env, capture_output=True, text=True, timeout=10)

    def test_fresh_nginx_full_lifecycle_child_is_traversable_and_private_leaves_stay_private(self):
        result = self.run_boundary()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.raw.parent, self.raw_parent)
        self.assertEqual(stat.S_IMODE(self.raw.stat().st_mode), 0o711)
        self.assertEqual(self.raw.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE((self.raw / "results").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.logs.stat().st_mode), 0o700)
        self.assertFalse(self.canonical.exists())

    def test_leaf_created_after_preflight_is_rejected_atomically(self):
        target = self.root / "late-target"
        target.mkdir()
        for kind in ("directory", "symlink"):
            with self.subTest(kind=kind):
                raw = self.raw_parent / ("late-" + kind)
                mutation = ('command mkdir -m 0700 "$RAW_DIR"' if kind == "directory"
                            else 'ln -s "' + str(target) + '" "$RAW_DIR"')
                prefix = ('mkdir() {\nif [ "$1" = -m ]; then\n' + mutation +
                          '\nfi\ncommand mkdir "$@"\n}\n')
                result = self.run_boundary(raw=raw, prefix=prefix)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.logs.exists())
                self.assertFalse((raw / "results").exists())
                if kind == "directory":
                    self.assertEqual(stat.S_IMODE(raw.stat().st_mode), 0o700)
                else:
                    self.assertTrue(raw.is_symlink())
                    self.assertEqual(list(target.iterdir()), [])

    def test_existing_child_is_rejected_without_mutation(self):
        self.raw.mkdir(mode=0o700)
        sentinel = self.raw / "sentinel"
        sentinel.write_text("retain")
        before = self.raw.stat()
        result = self.run_boundary()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("raw evidence directory already exists", result.stderr)
        self.assertEqual(self.raw.stat().st_ino, before.st_ino)
        self.assertEqual(stat.S_IMODE(self.raw.stat().st_mode), 0o700)
        self.assertEqual(sentinel.read_text(), "retain")
        self.assertFalse(self.logs.exists())

    def test_other_connector_and_generic_nginx_retain_caller_umask(self):
        for connector, profile in (("apache", "full_lifecycle"), ("nginx", "generic")):
            with self.subTest(connector=connector, profile=profile):
                raw = self.raw_parent / (connector + "-" + profile)
                result = self.run_boundary(connector, profile, raw)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(stat.S_IMODE(raw.stat().st_mode), 0o700)

    def test_symlink_child_and_ancestor_still_rejected(self):
        target = self.root / "target"
        target.mkdir()
        self.raw.symlink_to(target, target_is_directory=True)
        result = self.run_boundary()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not contain symlinks", result.stderr)
        self.assertEqual(list(target.iterdir()), [])
        link = self.root / "linked-parent"
        link.symlink_to(target, target_is_directory=True)
        result = self.run_boundary(raw=link / "child")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not contain symlinks", result.stderr)
        self.assertFalse((target / "child").exists())

    def test_checkout_and_relative_path_still_rejected(self):
        for raw in (source_path('forbidden-raw-run', root=ROOT), Path("relative-raw-run")):
            with self.subTest(raw=raw):
                result = self.run_boundary(raw=raw)
                self.assertEqual(result.returncode, 77)
                self.assertFalse(raw.exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
