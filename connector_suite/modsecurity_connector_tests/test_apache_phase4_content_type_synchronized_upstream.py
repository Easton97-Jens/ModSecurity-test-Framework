#!/usr/bin/env python3
"""Test the Parent-owned Apache Phase-4 synchronized-upstream wrapper."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import os
from pathlib import Path
import tempfile
import threading
import unittest


ROOT = connector_root()
TARGET = source_path('ci/runtime/lifecycle/apache_phase4_content_type_synchronized_upstream.py', root=ROOT)

class ApachePhase4ContentTypeSynchronizedUpstreamTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        temporary_root = Path(self._temporary_directory.name)
        self._control_root = temporary_root / "controls"
        self._control_root.mkdir()
        self._module = load_source(TARGET)
        self.assertIsNotNone(self._module.__spec__)
        self.assertIsNotNone(self._module.__spec__.loader)

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def control_args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "control_root": str(self._control_root),
            "ready_file": str(self._control_root / "ready.json"),
            "release_file": str(self._control_root / "release.json"),
            "paused_file": str(self._control_root / "paused.json"),
            "server_evidence_file": str(self._control_root / "evidence.json"),
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_control_paths_accept_distinct_files_beneath_existing_root(self) -> None:
        control_root, ready, release, paused, evidence = self._module.resolve_control_paths(
            self.control_args()
        )

        self.assertEqual(control_root, self._control_root.resolve())
        self.assertEqual(ready, self._control_root / "ready.json")
        self.assertEqual(release, self._control_root / "release.json")
        self.assertEqual(paused, self._control_root / "paused.json")
        self.assertEqual(evidence, self._control_root / "evidence.json")

    def test_control_paths_reject_a_file_outside_the_control_root(self) -> None:
        outside = Path(self._temporary_directory.name) / "outside-release.json"
        args = self.control_args(release_file=str(outside))

        with self.assertRaisesRegex(
            ValueError, "release file must resolve beneath control root"
        ):
            self._module.resolve_control_paths(args)

    def test_control_writer_rejects_an_outside_root_path_before_creation(self) -> None:
        outside = Path(self._temporary_directory.name) / "outside" / "control.json"

        with self.assertRaisesRegex(
            ValueError, "control file must resolve beneath control root"
        ):
            self._module.write_control_json(
                outside, {"schema_version": 1}, control_root=self._control_root
            )

        self.assertFalse(outside.parent.exists())

    def test_control_paths_reject_an_existing_symlink_escape(self) -> None:
        outside = Path(self._temporary_directory.name) / "outside"
        outside.mkdir()
        escape = self._control_root / "escape"
        escape.symlink_to(outside, target_is_directory=True)
        args = self.control_args(ready_file=str(escape / "ready.json"))

        with self.assertRaisesRegex(
            ValueError, "ready file must resolve beneath control root"
        ):
            self._module.resolve_control_paths(args)

    def test_missing_listener_is_recorded_as_a_server_failure(self) -> None:
        upstream = object.__new__(
            self._module.ContentTypedSynchronizedStreamingUpstream
        )
        upstream._listener = None
        upstream._connection = None
        upstream._closed = threading.Event()
        upstream._error = None

        upstream._serve_once()

        self.assertIsInstance(upstream._error, RuntimeError)
        self.assertTrue(upstream._closed.is_set())

    def test_interrupt_propagates_after_listener_cleanup(self) -> None:
        class InterruptingListener:
            def __init__(self) -> None:
                self.closed = False

            def accept(self) -> None:
                raise KeyboardInterrupt

            def close(self) -> None:
                self.closed = True

        listener = InterruptingListener()
        upstream = object.__new__(
            self._module.ContentTypedSynchronizedStreamingUpstream
        )
        upstream._listener = listener
        upstream._connection = None
        upstream._closed = threading.Event()
        upstream._error = None

        with self.assertRaises(KeyboardInterrupt):
            upstream._serve_once()

        self.assertIsNone(upstream._error)
        self.assertTrue(listener.closed)
        self.assertTrue(upstream._closed.is_set())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
