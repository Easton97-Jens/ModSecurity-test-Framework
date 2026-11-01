"""Focused no-side-effect contracts for the NGINX docroot projection."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = connector_root()
PROJECTOR_PATH = source_path('ci/runtime/common/prepare-nginx-docroot-projection.py', root=ROOT)
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)
NO_CRS_BASELINE = source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)
NATIVE_FIRST_BYTE = source_path('ci/runtime/lifecycle/run-native-first-byte.sh', root=ROOT)

projection = load_source(PROJECTOR_PATH)


class NginxDocrootProjectionTest(unittest.TestCase):
    maxDiff = None

    def test_paths_are_lexically_normalized_and_overlap_is_bidirectional(self) -> None:
        self.assertEqual(
            projection.normalized_absolute("/worker-visible/../projection", "projection parent"),
            Path("/projection"),
        )
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            projection.normalized_absolute("relative/projection", "projection parent")
        with self.assertRaisesRegex(ValueError, "filesystem root"):
            projection.normalized_absolute("/", "projection parent")
        self.assertTrue(projection.overlaps(Path("/private/build"), Path("/private/build/runtime")))
        self.assertTrue(projection.overlaps(Path("/private/build/runtime"), Path("/private/build")))
        self.assertFalse(projection.overlaps(Path("/private/build"), Path("/worker-visible")))

    def test_projection_plan_copies_only_the_two_allowlisted_files_without_real_fs_mutation(self) -> None:
        private_root = Path("/private/build")
        source_docroot = private_root / "runtime" / "htdocs"
        parent = Path("/worker-visible/projections")
        projected = parent / "docroot-unit-nonce"
        directory_metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)

        with (
            mock.patch.object(projection, "validate_source_docroot") as validate_source,
            mock.patch.object(projection, "ensure_private_parent") as ensure_parent,
            mock.patch.object(projection.os, "mkdir") as mkdir,
            mock.patch.object(Path, "lstat", return_value=directory_metadata),
            mock.patch.object(projection, "copy_regular_file") as copy_regular,
            mock.patch.object(projection, "finalize_projection_directory") as finalize_projection,
        ):
            result = projection.prepare_projection(
                source_docroot=source_docroot,
                private_root=private_root,
                projection_parent=parent,
                projection_root=projected,
                worker_gid=os.getegid(),
                avoid_roots=[private_root, Path("/private/raw"), Path("/private/evidence")],
            )

        self.assertEqual(result, projected)
        validate_source.assert_called_once_with(source_docroot, private_root)
        ensure_parent.assert_called_once_with(parent, "projection parent")
        mkdir.assert_called_once_with(projected, 0o700)
        self.assertEqual(
            copy_regular.call_args_list,
            [
                mock.call(source_docroot / "index.html", projected / "index.html", os.getegid()),
                mock.call(
                    source_docroot / "__modsec_smoke_ready", projected / "__modsec_smoke_ready", os.getegid()
                ),
            ],
        )
        finalize_projection.assert_called_once_with(projected, directory_metadata, os.getegid())

    def test_explicit_child_must_be_direct_fresh_and_safe_named(self) -> None:
        private_root = Path("/private/build")
        source_docroot = private_root / "runtime" / "htdocs"
        parent = Path("/worker-visible/projections")
        projection_root = parent / "docroot-unit-nonce"
        directory_metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)
        worker_gid = os.getegid()
        avoid_roots = [private_root]
        different_parent_root = Path("/different-parent/registered")
        hidden_projection_root = parent / ".hidden"

        with mock.patch.object(projection, "validate_source_docroot"):
            with self.assertRaisesRegex(ValueError, "explicit safe parent and fresh root"):
                projection.prepare_projection(
                    source_docroot=source_docroot,
                    private_root=private_root,
                    projection_parent=None,
                    projection_root=projection_root,
                    worker_gid=worker_gid,
                    avoid_roots=avoid_roots,
                )
            with self.assertRaisesRegex(ValueError, "explicit safe parent and fresh root"):
                projection.prepare_projection(
                    source_docroot=source_docroot,
                    private_root=private_root,
                    projection_parent=parent,
                    projection_root=None,
                    worker_gid=worker_gid,
                    avoid_roots=avoid_roots,
                )

        with (
            mock.patch.object(projection, "validate_source_docroot"),
            mock.patch.object(projection, "ensure_private_parent"),
            mock.patch.object(projection.os, "mkdir") as mkdir,
            mock.patch.object(Path, "lstat", return_value=directory_metadata),
            mock.patch.object(projection, "copy_regular_file"),
            mock.patch.object(projection, "finalize_projection_directory"),
        ):
            result = projection.prepare_projection(
                source_docroot=source_docroot,
                private_root=private_root,
                projection_parent=parent,
                projection_root=projection_root,
                worker_gid=worker_gid,
                avoid_roots=avoid_roots,
            )

        self.assertEqual(result, projection_root)
        mkdir.assert_called_once_with(projection_root, 0o700)

        with mock.patch.object(projection, "validate_source_docroot"):
            with self.assertRaisesRegex(ValueError, "direct child"):
                projection.prepare_projection(
                    source_docroot=source_docroot,
                    private_root=private_root,
                    projection_parent=parent,
                    projection_root=different_parent_root,
                    worker_gid=worker_gid,
                    avoid_roots=avoid_roots,
                )
            with self.assertRaisesRegex(ValueError, "unsafe"):
                projection.prepare_projection(
                    source_docroot=source_docroot,
                    private_root=private_root,
                    projection_parent=parent,
                    projection_root=hidden_projection_root,
                    worker_gid=worker_gid,
                    avoid_roots=avoid_roots,
                )

    def test_overlap_is_rejected_before_any_fresh_child_is_created(self) -> None:
        private_root = Path("/private/build")
        source_docroot = private_root / "runtime" / "htdocs"
        overlapping_parent = private_root / "worker-visible"
        rejected_projection_root = Path("/private/build/worker-visible/docroot")
        worker_gid = os.getegid()
        avoid_roots = [private_root]

        with (
            mock.patch.object(projection, "validate_source_docroot"),
            mock.patch.object(projection, "ensure_private_parent"),
            mock.patch.object(projection.os, "mkdir") as mkdir,
        ):
            with self.assertRaisesRegex(ValueError, "overlaps a private runtime root"):
                projection.prepare_projection(
                    source_docroot=source_docroot,
                    private_root=private_root,
                    projection_parent=overlapping_parent,
                    projection_root=rejected_projection_root,
                    worker_gid=worker_gid,
                    avoid_roots=avoid_roots,
                )
        mkdir.assert_not_called()

    def test_harness_and_lifecycle_routes_keep_projection_opt_in_and_narrow(self) -> None:
        helper = PROJECTOR_PATH.read_text(encoding="utf-8")
        harness = HARNESS.read_text(encoding="utf-8")
        no_crs = NO_CRS_BASELINE.read_text(encoding="utf-8")
        first_byte = NATIVE_FIRST_BYTE.read_text(encoding="utf-8")

        for fragment in (
            "PROJECTED_FILENAMES = (\"index.html\", \"__modsec_smoke_ready\")",
            "os.O_RDONLY | os.O_NOFOLLOW",
            "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW",
            "metadata.st_uid != os.geteuid()",
            "metadata.st_mode & 0o022",
            "metadata.st_mode & 0o044",
            "require_no_symlink_directory",
            "projection parent overlaps a private runtime root",
            "projection root already exists",
            "validate_worker_gid",
            "os.fchown",
            "os.fchmod",
            "0o640",
            "0o710",
            "finalize_projection_directory",
        ):
            self.assertIn(fragment, helper)
        self.assertNotIn("os.chmod(", helper)

        for fragment in (
            'NGINX_DOCROOT_PROJECTION="${NGINX_DOCROOT_PROJECTION:-0}"',
            'PRIVATE_DOCROOT="$RUNTIME_ROOT/htdocs"',
            '--docroot "$PRIVATE_DOCROOT"',
            "project_nginx_worker_docroot",
            '--source-docroot "$PRIVATE_DOCROOT"',
            '--private-root "$BUILD_ROOT"',
            '--worker-gid "$NGINX_WORKER_RESOLVED_GID"',
            '--avoid-root "$BUILD_ROOT"',
            'NGINX_DOCROOT_PROJECTION_ROOT="${NGINX_DOCROOT_PROJECTION_ROOT:-}"',
            'if ! "$@" > "$LOG_DIR/docroot-projection.path"',
            'NGINX_DOCROOT_PROJECTION_PATH=$(sed -n \'1p\' "$LOG_DIR/docroot-projection.path")',
            'NGINX docroot projection helper emitted an invalid path result',
            '--safe-root "$DOCROOT"',
            "Private runtime root hidden from worker",
            "Rules remain private",
            "NGINX worker state writable",
            "NGINX server log root writable",
            "Private harness logs hidden from worker",
            "Memcheck evidence hidden from worker",
            "require_private_worker_path_separation",
            "validate_nginx_worker_isolation",
            "requires root to establish a distinct verified worker identity",
            "NGINX_WORKER_USER_DIRECTIVE",
            "requires an explicit safe parent and fresh root",
        ):
            self.assertIn(fragment, harness)
        self.assertNotIn('chmod -R u+rwX,go+rX "$NGINX_DOCROOT_PROJECTION_ROOT"', harness)
        self.assertNotIn('chown -R "$NGINX_WORKER_USER:$worker_group" "$NGINX_DOCROOT_PROJECTION_ROOT"', harness)
        self.assertNotIn('chmod -R u+rwX,go+rX "$NGINX_HARNESS_WORK_ROOT"', harness)
        self.assertNotIn('chown -R "$NGINX_WORKER_USER:$worker_group" "$NGINX_HARNESS_WORK_ROOT"', harness)

        template = (source_path('connectors/nginx/harness/nginx_smoke.conf', root=ROOT)).read_text(
            encoding="utf-8"
        )
        for temporary_path in (
            "client_body_temp_path",
            "proxy_temp_path",
            "fastcgi_temp_path",
            "uwsgi_temp_path",
            "scgi_temp_path",
        ):
            self.assertIn(f'{temporary_path} "@@NGINX_WORKER_STATE_ROOT@@/', template)
        self.assertIn('error_log "@@NGINX_SERVER_LOG_ROOT@@/error.log" debug;', template)
        self.assertIn('access_log "@@NGINX_SERVER_LOG_ROOT@@/access.log";', template)
        self.assertIn("@@NGINX_WORKER_USER_DIRECTIVE@@", template)
        self.assertNotIn('@@RUNTIME_ROOT@@/client_body_temp', template)
        self.assertIn('NGINX_PHASE4_LOG_FILE="$LOG_DIR/phase4.log"', harness)

        self.assertIn('NGINX_DOCROOT_PROJECTION=1', no_crs)
        self.assertIn('NGINX_DOCROOT_PROJECTION="$NGINX_DOCROOT_PROJECTION"', no_crs)
        self.assertIn('NGINX_DOCROOT_PROJECTION=1', first_byte)
        self.assertIn('NGINX_DOCROOT_PROJECTION="${NGINX_DOCROOT_PROJECTION:-0}"', first_byte)
        self.assertIn('phase4_log=$log_root/phase4.log', first_byte)


class NginxDocrootProjectionFilesystemTest(unittest.TestCase):
    @staticmethod
    def _has_worker_traversable_ancestors(path: Path) -> bool:
        current = Path("/")
        for component in path.parts[1:]:
            current /= component
            try:
                metadata = current.lstat()
            except OSError:
                return False
            if not stat.S_ISDIR(metadata.st_mode) or not metadata.st_mode & stat.S_IXOTH:
                return False
        return True

    @staticmethod
    @contextmanager
    def _worker_traversable_temporary_directory():
        candidates = (Path(tempfile.gettempdir()), Path("/tmp"), Path("/dev/shm"))
        attempted: set[Path] = set()
        failures: list[str] = []

        for candidate in candidates:
            if candidate in attempted:
                continue
            attempted.add(candidate)
            if not NginxDocrootProjectionFilesystemTest._has_worker_traversable_ancestors(
                candidate
            ):
                failures.append(f"{candidate}: non-traversable ancestor")
                continue
            try:
                temporary_directory = tempfile.TemporaryDirectory(dir=candidate)
            except OSError as exc:
                failures.append(f"{candidate}: {exc}")
                continue
            try:
                yield temporary_directory.name
            finally:
                temporary_directory.cleanup()
            return

        raise RuntimeError(
            "no worker-traversable temporary directory available: " + "; ".join(failures)
        )

    @staticmethod
    def _layout(root: Path) -> tuple[Path, Path, Path]:
        """Create a real, worker-traversable test layout below one temp root."""

        root.chmod(0o711)
        private_root = root / "private-build"
        source_docroot = private_root / "runtime" / "htdocs"
        source_docroot.mkdir(parents=True, mode=0o700)
        projection_parent = root / "projections"
        projection_parent.mkdir(mode=0o711)
        projection_parent.chmod(0o711)
        return private_root, source_docroot, projection_parent

    @staticmethod
    def _write_allowlisted_sources(source_docroot: Path) -> None:
        (source_docroot / "index.html").write_text("projected index\n", encoding="utf-8")
        (source_docroot / "__modsec_smoke_ready").write_text("ready\n", encoding="utf-8")

    @staticmethod
    def _prepare(
        source_docroot: Path,
        private_root: Path,
        projection_parent: Path,
        projection_root: Path,
    ) -> Path:
        return projection.prepare_projection(
            source_docroot=source_docroot,
            private_root=private_root,
            projection_parent=projection_parent,
            projection_root=projection_root,
            worker_gid=os.getegid(),
            avoid_roots=[private_root],
        )

    def test_real_filesystem_copy_is_allowlisted_and_has_expected_modes(self) -> None:
        with self._worker_traversable_temporary_directory() as temporary_directory:
            root = Path(temporary_directory)
            private_root, source_docroot, projection_parent = self._layout(root)
            self._write_allowlisted_sources(source_docroot)
            (source_docroot / "not-projected.txt").write_text("private\n", encoding="utf-8")
            projection_root = projection_parent / "explicit-docroot"

            result = self._prepare(
                source_docroot,
                private_root,
                projection_parent,
                projection_root,
            )

            self.assertEqual(result, projection_root)
            self.assertEqual(
                {entry.name for entry in projection_root.iterdir()},
                set(projection.PROJECTED_FILENAMES),
            )
            self.assertEqual(
                (projection_root / "index.html").read_text(encoding="utf-8"),
                "projected index\n",
            )
            self.assertEqual(
                (projection_root / "__modsec_smoke_ready").read_text(encoding="utf-8"),
                "ready\n",
            )
            self.assertFalse((projection_root / "not-projected.txt").exists())
            self.assertEqual(stat.S_IMODE(projection_root.lstat().st_mode), 0o710)
            self.assertEqual(projection_root.lstat().st_gid, os.getegid())
            for filename in projection.PROJECTED_FILENAMES:
                projected_file = projection_root / filename
                self.assertEqual(stat.S_IMODE(projected_file.lstat().st_mode), 0o640)
                self.assertEqual(projected_file.lstat().st_gid, os.getegid())

    def test_group_or_world_readable_or_writable_parent_is_rejected(self) -> None:
        unsafe_modes = (
            ("group-readable", 0o751, "group- or other-readable"),
            ("world-readable", 0o715, "group- or other-readable"),
            ("group-writable", 0o731, "group- or other-writable"),
            ("world-writable", 0o713, "group- or other-writable"),
        )

        with self._worker_traversable_temporary_directory() as temporary_directory:
            root = Path(temporary_directory)
            private_root, source_docroot, _ = self._layout(root)
            self._write_allowlisted_sources(source_docroot)

            for name, mode, message in unsafe_modes:
                with self.subTest(name=name):
                    projection_parent = root / f"{name}-parent"
                    projection_parent.mkdir()
                    projection_parent.chmod(mode)
                    projection_root = projection_parent / "explicit-docroot"

                    with self.assertRaisesRegex(ValueError, message):
                        self._prepare(
                            source_docroot,
                            private_root,
                            projection_parent,
                            projection_root,
                        )

                    self.assertFalse(projection_root.exists())

    def test_projection_reapplies_group_only_modes_under_restrictive_umask(self) -> None:
        with self._worker_traversable_temporary_directory() as temporary_directory:
            root = Path(temporary_directory)
            private_root, source_docroot, projection_parent = self._layout(root)
            self._write_allowlisted_sources(source_docroot)
            projection_root = projection_parent / "umask-docroot"
            original_umask = os.umask(0o077)
            try:
                self._prepare(
                    source_docroot,
                    private_root,
                    projection_parent,
                    projection_root,
                )
            finally:
                os.umask(original_umask)

            self.assertEqual(stat.S_IMODE(projection_root.lstat().st_mode), 0o710)
            self.assertEqual(projection_root.lstat().st_gid, os.getegid())
            for filename in projection.PROJECTED_FILENAMES:
                projected_file = projection_root / filename
                self.assertEqual(stat.S_IMODE(projected_file.lstat().st_mode), 0o640)
                self.assertEqual(projected_file.lstat().st_gid, os.getegid())

    def test_existing_explicit_child_is_rejected_without_modifying_it(self) -> None:
        with self._worker_traversable_temporary_directory() as temporary_directory:
            root = Path(temporary_directory)
            private_root, source_docroot, projection_parent = self._layout(root)
            self._write_allowlisted_sources(source_docroot)
            projection_root = projection_parent / "explicit-docroot"
            projection_root.mkdir(mode=0o700)
            marker = projection_root / "existing-marker"
            marker.write_text("keep\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "projection root already exists"):
                self._prepare(
                    source_docroot,
                    private_root,
                    projection_parent,
                    projection_root,
                )

            self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
            self.assertEqual(
                {entry.name for entry in projection_root.iterdir()},
                {"existing-marker"},
            )

    def test_symlinked_projection_parent_is_rejected_before_child_creation(self) -> None:
        with self._worker_traversable_temporary_directory() as temporary_directory:
            root = Path(temporary_directory)
            private_root, source_docroot, _ = self._layout(root)
            self._write_allowlisted_sources(source_docroot)
            actual_parent = root / "actual-projection-parent"
            actual_parent.mkdir(mode=0o711)
            actual_parent.chmod(0o711)
            projection_parent = root / "projection-parent-link"
            projection_parent.symlink_to(actual_parent, target_is_directory=True)
            projection_root = projection_parent / "explicit-docroot"

            with self.assertRaisesRegex(ValueError, "contains a symbolic link"):
                self._prepare(
                    source_docroot,
                    private_root,
                    projection_parent,
                    projection_root,
                )

            self.assertFalse(projection_root.exists())

    def test_symlinked_source_docroot_and_source_file_are_rejected(self) -> None:
        with self._worker_traversable_temporary_directory() as temporary_directory:
            root = Path(temporary_directory)
            private_root, source_docroot, projection_parent = self._layout(root)

            real_source_docroot = private_root / "real-htdocs"
            real_source_docroot.mkdir()
            self._write_allowlisted_sources(real_source_docroot)
            source_docroot_link = private_root / "htdocs-link"
            source_docroot_link.symlink_to(real_source_docroot, target_is_directory=True)
            linked_docroot_projection = projection_parent / "linked-docroot"

            with self.assertRaisesRegex(ValueError, "source docroot contains a symbolic link"):
                self._prepare(
                    source_docroot_link,
                    private_root,
                    projection_parent,
                    linked_docroot_projection,
                )

            self.assertFalse(linked_docroot_projection.exists())

            self._write_allowlisted_sources(source_docroot)
            outside_index = root / "outside-index.html"
            outside_index.write_text("outside\n", encoding="utf-8")
            (source_docroot / "index.html").unlink()
            (source_docroot / "index.html").symlink_to(outside_index)
            linked_file_projection = projection_parent / "linked-file"

            with self.assertRaisesRegex(ValueError, "cannot open projected source file"):
                self._prepare(
                    source_docroot,
                    private_root,
                    projection_parent,
                    linked_file_projection,
                )

            self.assertTrue(linked_file_projection.is_dir())
            self.assertEqual(stat.S_IMODE(linked_file_projection.lstat().st_mode), 0o700)
            self.assertEqual(list(linked_file_projection.iterdir()), [])

    def test_missing_second_source_keeps_new_projection_unserved(self) -> None:
        with self._worker_traversable_temporary_directory() as temporary_directory:
            root = Path(temporary_directory)
            private_root, source_docroot, projection_parent = self._layout(root)
            (source_docroot / "index.html").write_text("projected index\n", encoding="utf-8")
            projection_root = projection_parent / "explicit-docroot"

            with self.assertRaisesRegex(ValueError, "__modsec_smoke_ready"):
                self._prepare(
                    source_docroot,
                    private_root,
                    projection_parent,
                    projection_root,
                )

            self.assertTrue(projection_root.is_dir())
            self.assertEqual(stat.S_IMODE(projection_root.lstat().st_mode), 0o700)
            self.assertEqual(
                (projection_root / "index.html").read_text(encoding="utf-8"),
                "projected index\n",
            )
            self.assertFalse((projection_root / "__modsec_smoke_ready").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
