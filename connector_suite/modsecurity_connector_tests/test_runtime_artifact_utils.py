"""Focused contracts for shared private-runtime artifact helpers."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
CI_LIB = source_path('ci/lib', root=ROOT)


import modsecurity_connector_ci.lib.runtime_path_utils as RUNTIME_PATH_UTILS
from modsecurity_connector_ci.lib.runtime_path_utils import append_runtime_artifact_text, move_runtime_artifact_atomic, open_private_runtime_root, prepare_verified_runtime_artifact_root, read_runtime_artifact_text, runtime_artifact_path, runtime_or_source_artifact_path, verified_runtime_artifact_root, write_runtime_artifact_text_atomic


def load_helper(name: str, path: Path) -> object:
    module = load_source(path)
    return module


class RuntimeArtifactUtilsTest(unittest.TestCase):
    def private_root(self, temporary: str) -> Path:
        return verified_runtime_artifact_root(Path(temporary) / "runtime")

    def test_descriptor_backed_private_root_requires_existing_exact_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="private-runtime-root-") as temporary:
            parent = Path(temporary)
            root = parent / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            with open_private_runtime_root(root) as handle:
                self.assertEqual(handle.identity, (root.stat().st_dev, root.stat().st_ino))
                handle.create_text("observation.txt", "first\n")
                self.assertEqual(handle.read_text("observation.txt"), "first\n")
                handle.replace_text("observation.txt", "second\n")
                self.assertEqual(handle.read_text("observation.txt"), "second\n")
            self.assertEqual(stat.S_IMODE((root / "observation.txt").stat().st_mode), 0o600)

            with self.assertRaisesRegex(ValueError, "already exist"):
                open_private_runtime_root(parent / "missing")
            broad = parent / "broad"
            broad.mkdir(mode=0o755)
            with self.assertRaisesRegex(ValueError, "mode 0700"):
                open_private_runtime_root(broad)

    def test_descriptor_backed_private_root_closes_rejected_leaf_descriptors(self) -> None:
        descriptor_directory = Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            self.skipTest("descriptor accounting is unavailable")
        with tempfile.TemporaryDirectory(prefix="private-runtime-rejected-leaf-") as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            descriptor_count = len(tuple(descriptor_directory.iterdir()))
            with (
                mock.patch.object(
                    RUNTIME_PATH_UTILS, "is_safe_runtime_root", return_value=True
                ),
                mock.patch.object(
                    RUNTIME_PATH_UTILS,
                    "_validate_runtime_ancestor",
                    side_effect=ValueError("rejected leaf"),
                ),
            ):
                for _ in range(20):
                    with self.assertRaisesRegex(ValueError, "rejected leaf"):
                        open_private_runtime_root(root)
            self.assertEqual(len(tuple(descriptor_directory.iterdir())), descriptor_count)

    def test_descriptor_backed_replacement_enforces_private_mode_with_nonstandard_umask(self) -> None:
        with tempfile.TemporaryDirectory(prefix="private-runtime-umask-") as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            previous_umask = os.umask(0o000)
            try:
                with open_private_runtime_root(root) as handle:
                    handle.create_text("result.txt", "before\n")
                    with mock.patch.object(
                        RUNTIME_PATH_UTILS.os,
                        "fchmod",
                        wraps=os.fchmod,
                    ) as chmod:
                        handle.replace_text("result.txt", "after\n")
                    self.assertTrue(
                        any(call.args[1] == 0o600 for call in chmod.call_args_list)
                    )
                    self.assertEqual(handle.read_text("result.txt"), "after\n")
                self.assertEqual(stat.S_IMODE((root / "result.txt").stat().st_mode), 0o600)
            finally:
                os.umask(previous_umask)

    def test_descriptor_backed_private_root_rejects_links_hardlinks_and_unsafe_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="private-runtime-controls-") as temporary:
            parent = Path(temporary)
            root = parent / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            outside = parent / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (root / "linked.txt").symlink_to(outside)
            with open_private_runtime_root(root) as handle:
                with self.assertRaises((OSError, ValueError)):
                    handle.read_text("linked.txt")
                with self.assertRaisesRegex(ValueError, "direct filename"):
                    handle.create_text("nested/file.txt", "nope")
                handle.create_text("original.txt", "safe\n")
                os.link(root / "original.txt", root / "hardlink.txt")
                with self.assertRaisesRegex(ValueError, "additional hard links"):
                    handle.read_text("original.txt")
                with self.assertRaisesRegex(ValueError, "additional hard links"):
                    handle.replace_text("original.txt", "unsafe\n")
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")

    def test_descriptor_backed_private_root_rejects_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="private-runtime-replacement-") as temporary:
            parent = Path(temporary)
            root = parent / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            with open_private_runtime_root(root) as handle:
                root.rename(parent / "old-root")
                root.mkdir(mode=0o700)
                os.chmod(root, 0o700)
                with self.assertRaisesRegex(ValueError, "path was replaced"):
                    handle.create_text("new.txt", "must fail\n")

    def test_symbolic_link_runtime_error_fails_closed(self) -> None:
        with mock.patch.object(Path, "resolve", side_effect=RuntimeError("loop")):
            self.assertTrue(RUNTIME_PATH_UTILS._contains_symbolic_link(Path("/tmp/root")))

    def test_root_validation_rejects_relative_and_broad_locations(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            verified_runtime_artifact_root("relative-runtime")
        with self.assertRaisesRegex(ValueError, "unsafe for writes"):
            verified_runtime_artifact_root("/")
        with self.assertRaisesRegex(ValueError, "unsafe for writes"):
            prepare_verified_runtime_artifact_root("/", env={})

    def test_prepared_root_preserves_input_precedence_and_relative_semantics(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-prepared-root-") as temporary:
            parent = Path(temporary)
            explicit_root = parent / "explicit"
            environment_root = parent / "environment"
            fallback_root = parent / "fallback"
            environment = {"VERIFIED_RUN_ROOT": str(environment_root)}

            self.assertEqual(
                prepare_verified_runtime_artifact_root(
                    explicit_root,
                    env=environment,
                    fallback=fallback_root,
                ),
                explicit_root,
            )
            self.assertEqual(
                prepare_verified_runtime_artifact_root(
                    env=environment,
                    fallback=fallback_root,
                ),
                environment_root,
            )
            self.assertEqual(
                prepare_verified_runtime_artifact_root(
                    env={},
                    fallback=fallback_root,
                ),
                fallback_root,
            )

            previous_directory = Path.cwd()
            try:
                os.chdir(parent)
                relative_root = prepare_verified_runtime_artifact_root(
                    "relative-root",
                    env={},
                    fallback=fallback_root,
                )
            finally:
                os.chdir(previous_directory)

            for root in (explicit_root, environment_root, fallback_root, relative_root):
                with self.subTest(root=root):
                    self.assertTrue(root.is_dir())
                    self.assertFalse(root.is_symlink())
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode) & 0o022, 0)

    def test_path_validation_rejects_non_descendants_and_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-path-") as temporary:
            root = self.private_root(temporary)
            target = root / "artifacts" / "result.txt"
            self.assertEqual(
                runtime_artifact_path(root, target, "result"),
                target,
            )
            relative_result = Path("relative.txt")
            outside_result = root.parent / "outside.txt"
            with self.assertRaisesRegex(ValueError, "must be absolute"):
                runtime_artifact_path(root, relative_result, "result")
            with self.assertRaisesRegex(ValueError, "below the runtime root"):
                runtime_artifact_path(root, root, "result")
            with self.assertRaisesRegex(ValueError, "below the runtime root"):
                runtime_artifact_path(root, outside_result, "result")

            final_link = root / "final-link.txt"
            final_link.symlink_to(root.parent / "outside.txt")
            with self.assertRaisesRegex(ValueError, "below the runtime root|symbolic link"):
                runtime_artifact_path(root, final_link, "result")

            escaped_parent = root / "escaped"
            escaped_parent.symlink_to(root.parent, target_is_directory=True)
            escaped_result = escaped_parent / "result.txt"
            with self.assertRaisesRegex(ValueError, "below the runtime root"):
                runtime_artifact_path(root, escaped_result, "result")

    def test_runtime_or_source_artifact_path_accepts_only_project_sources_or_private_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-or-source-artifact-") as temporary:
            root = self.private_root(temporary)
            runtime_result = root / "records" / "result.json"
            source_file = source_path('Makefile', root=ROOT)
            outside_file = Path(temporary) / "outside.txt"
            outside_file.write_text("outside\n", encoding="utf-8")

            self.assertEqual(
                runtime_or_source_artifact_path(root, runtime_result, "result"),
                runtime_result,
            )
            self.assertEqual(
                runtime_or_source_artifact_path(root, source_file, "source", must_exist=True),
                source_file,
            )
            with self.assertRaisesRegex(ValueError, "below the runtime root"):
                runtime_or_source_artifact_path(root, outside_file, "outside", must_exist=True)

    def test_shared_text_operations_keep_regular_private_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-text-") as temporary:
            root = self.private_root(temporary)
            target = root / "records" / "event.txt"
            self.assertEqual(
                append_runtime_artifact_text(root, target, "first\n", "event"),
                target,
            )
            append_runtime_artifact_text(root, target, "second\n", "event")
            self.assertEqual(
                read_runtime_artifact_text(root, target, "event"),
                "first\nsecond\n",
            )
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

            write_runtime_artifact_text_atomic(root, target, "replacement\n", "event")
            self.assertEqual(
                read_runtime_artifact_text(root, target, "event"),
                "replacement\n",
            )
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(list(target.parent.glob(".event.txt.*.tmp")), [])

            directory = root / "directory-target"
            directory.mkdir()
            with self.assertRaisesRegex(ValueError, "regular file"):
                append_runtime_artifact_text(root, directory, "nope", "directory")
            with self.assertRaisesRegex(ValueError, "regular file"):
                write_runtime_artifact_text_atomic(root, directory, "nope", "directory")
            with self.assertRaisesRegex(ValueError, "existing regular file"):
                read_runtime_artifact_text(root, directory, "directory")

    def test_atomic_recheck_rejects_a_replaced_nonregular_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-recheck-") as temporary:
            root = self.private_root(temporary)
            target = root / "observation.json"
            target.write_text("old\n", encoding="utf-8")
            original_stat = RUNTIME_PATH_UTILS.os.stat
            replacement = list(target.stat())
            replacement[0] = stat.S_IFDIR | 0o700
            target_stat_calls = 0

            def rechecked_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
                nonlocal target_stat_calls
                if (
                    path == target.name
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                ):
                    target_stat_calls += 1
                    if target_stat_calls == 2:
                        return os.stat_result(replacement)
                return original_stat(path, *args, **kwargs)

            with mock.patch.object(RUNTIME_PATH_UTILS.os, "stat", side_effect=rechecked_stat):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    write_runtime_artifact_text_atomic(root, target, "new\n", "observation")

            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(list(root.glob(".observation.json.*.tmp")), [])

    def test_atomic_name_collision_keeps_the_existing_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-collision-") as temporary:
            root = self.private_root(temporary)
            target = root / "observation.json"
            collision = root / ".observation.json.already-there.tmp"
            collision.write_text("retain me\n", encoding="utf-8")
            with mock.patch.object(
                RUNTIME_PATH_UTILS.secrets,
                "token_hex",
                side_effect=["already-there", "fresh-name"],
            ):
                write_runtime_artifact_text_atomic(root, target, "new\n", "observation")

            self.assertEqual(collision.read_text(encoding="utf-8"), "retain me\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
            self.assertEqual(list(root.glob(".observation.json.*.tmp")), [collision])

    def test_missing_nofollow_or_directory_support_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-flags-") as temporary:
            root = self.private_root(temporary)
            target = root / "record.txt"
            with mock.patch.object(RUNTIME_PATH_UTILS.os, "O_NOFOLLOW", None):
                with self.assertRaises(ValueError):
                    append_runtime_artifact_text(root, target, "data", "record")
            with mock.patch.object(RUNTIME_PATH_UTILS.os, "O_DIRECTORY", None):
                with self.assertRaises(ValueError):
                    append_runtime_artifact_text(root, target, "data", "record")
            self.assertFalse(target.exists())

    def test_atomic_move_keeps_private_regular_artifacts_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-move-") as temporary:
            parent = Path(temporary)
            source_root = self.private_root(str(parent / "source-parent"))
            destination_root = self.private_root(str(parent / "destination-parent"))
            source = source_root / "producer" / "events.jsonl"
            destination = destination_root / "raw" / "events.jsonl"
            source.parent.mkdir()
            source.write_text('{"event":"safe"}\n', encoding="utf-8")

            self.assertEqual(
                move_runtime_artifact_atomic(
                    source_root, source, destination_root, destination, "event stream"
                ),
                destination,
            )
            self.assertFalse(source.exists())
            self.assertEqual(destination.read_text(encoding="utf-8"), '{"event":"safe"}\n')
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(list(destination.parent.glob(".events.jsonl.*.tmp")), [])

            link_source = source_root / "producer" / "link.json"
            link_source.symlink_to(destination)
            with self.assertRaisesRegex(
                ValueError, "symbolic link|must not use symbolic links|below the runtime root"
            ):
                move_runtime_artifact_atomic(
                    source_root,
                    link_source,
                    destination_root,
                    destination_root / "raw" / "link.json",
                    "linked source",
                )

            link_destination = destination_root / "raw" / "link-destination.json"
            link_destination.symlink_to(destination)
            source.write_text("second\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "symbolic link|must not use symbolic links|below the runtime root"
            ):
                move_runtime_artifact_atomic(
                    source_root,
                    source,
                    destination_root,
                    link_destination,
                    "linked destination",
                )
            self.assertEqual(source.read_text(encoding="utf-8"), "second\n")

    def test_atomic_move_does_not_unlink_a_replaced_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-move-recheck-") as temporary:
            parent = Path(temporary)
            source_root = self.private_root(str(parent / "source-parent"))
            destination_root = self.private_root(str(parent / "destination-parent"))
            source = source_root / "producer" / "result.json"
            destination = destination_root / "raw" / "result.json"
            source.parent.mkdir()
            source.write_text("original\n", encoding="utf-8")
            replacement = list(source.stat())
            replacement[1] += 1
            original_stat = RUNTIME_PATH_UTILS.os.stat

            def replaced_source_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
                if (
                    path == source.name
                    and kwargs.get("dir_fd") is not None
                    and kwargs.get("follow_symlinks") is False
                ):
                    return os.stat_result(replacement)
                return original_stat(path, *args, **kwargs)

            with mock.patch.object(RUNTIME_PATH_UTILS.os, "stat", side_effect=replaced_source_stat):
                with self.assertRaisesRegex(ValueError, "source changed while being moved"):
                    move_runtime_artifact_atomic(
                        source_root, source, destination_root, destination, "result"
                    )

            self.assertEqual(source.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(destination.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(list(destination.parent.glob(".result.json.*.tmp")), [])

    def test_atomic_move_completes_short_writes_before_replacing_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-move-short-write-") as temporary:
            parent = Path(temporary)
            source_root = self.private_root(str(parent / "source-parent"))
            destination_root = self.private_root(str(parent / "destination-parent"))
            source = source_root / "producer" / "result.json"
            destination = destination_root / "raw" / "result.json"
            source.parent.mkdir()
            contents = "one short write is not enough\n"
            source.write_text(contents, encoding="utf-8")
            original_write = RUNTIME_PATH_UTILS.os.write

            def short_write(descriptor: int, data: bytes) -> int:
                return original_write(descriptor, data[:1])

            with mock.patch.object(RUNTIME_PATH_UTILS.os, "write", side_effect=short_write):
                move_runtime_artifact_atomic(
                    source_root, source, destination_root, destination, "result"
                )

            self.assertFalse(source.exists())
            self.assertEqual(destination.read_text(encoding="utf-8"), contents)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_connector_facades_preserve_serialization_and_private_modes(self) -> None:
        haproxy = load_helper(
            "haproxy_runtime_artifacts_contract",
            source_path('connectors/haproxy/harness/runtime_artifacts.py', root=ROOT),
        )
        envoy = load_helper(
            "envoy_smoke_helper_artifact_contract",
            source_path('connectors/envoy/harness/envoy_smoke_helper.py', root=ROOT),
        )
        with tempfile.TemporaryDirectory(prefix="runtime-artifact-facades-") as temporary:
            root = self.private_root(temporary)
            haproxy_path = root / "haproxy-events.jsonl"
            envoy_path = root / "envoy-observation.json"
            haproxy.append_text(root, haproxy_path, "event\n", "HAProxy event")
            self.assertEqual(haproxy.read_text(root, haproxy_path, "HAProxy event"), "event\n")
            self.assertEqual(stat.S_IMODE(haproxy_path.stat().st_mode), 0o600)

            envoy.write_json_atomic(root, envoy_path, {"answer": 42}, "Envoy observation")
            self.assertEqual(
                envoy_path.read_text(encoding="utf-8"),
                "{\n  \"answer\": 42\n}\n",
            )
            envoy.append_jsonl(root, root / "envoy-events.jsonl", {"event": "ok"}, "Envoy event")
            self.assertEqual(stat.S_IMODE(envoy_path.stat().st_mode), 0o600)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
