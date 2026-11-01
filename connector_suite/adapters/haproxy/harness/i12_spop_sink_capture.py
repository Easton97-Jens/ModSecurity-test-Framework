#!/usr/bin/env python3
"""Retain argv, exits and physical artifacts from native SPOP sink controls.

Runs the existing production-source sink tests, including their unsafe
mutations, with compiler/process commands proxied through RTK. This is native
C and physical stdio evidence, independent of private HAProxy host evidence.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest

ROOT = connector_root()

from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory, fixed_runtime_temp_parent, open_private_runtime_root


@contextmanager
def prepare_output(output):
    """Create a fresh private storage child before any fixture or subprocess."""
    authorized = fixed_runtime_temp_parent() / "codex" / "ModSecurity-conector"
    if (not output.is_absolute() or ".." in output.parts or output == authorized
            or not output.is_relative_to(authorized) or output != output.resolve()):
        raise ValueError("output must be a fresh absolute directory below the external project root")
    parent = ensure_safe_runtime_directory(output.parent)
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_descriptor = os.open(parent, flags)
    try:
        os.mkdir(output.name, mode=0o700, dir_fd=parent_descriptor)
        created = os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        with open_private_runtime_root(output) as directory:
            if directory.identity != (created.st_dev, created.st_ino):
                raise ValueError("capture output was replaced during creation")
            yield directory
    finally:
        os.close(parent_descriptor)


def retain_command_output(directory, name, data):
    """Preserve subprocess bytes while creating only private exclusive leaves."""
    if isinstance(data, str):
        directory.create_text(name, data)
        return
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory.descriptor)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
    os.fstat(directory.descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    output = arguments.output
    with ExitStack() as stack:
        try:
            directory = stack.enter_context(prepare_output(output))
        except (OSError, ValueError) as error:
            parser.error(str(error))
        return capture(output, directory)


def capture(output, directory):
    os.environ["RUNNER_TEMP"] = str(output)
    from modsecurity_connector_tests.test_haproxy_spop_event_sink_failures import HaproxySpopEventSinkFailureTests

    receipts = []
    original = subprocess.run

    def observed(argv, **kwargs):
        actual = ["rtk", "bypass", *argv]
        started = time.time_ns()
        result = original(actual, **kwargs)
        index = len(receipts)
        for name in ("stdout", "stderr"):
            data = getattr(result, name)
            if data is not None:
                retain_command_output(directory, f"command-{index:03d}.{name}", data)
        receipts.append({"argv": actual, "cwd": str(kwargs.get("cwd", Path.cwd())),
                         "exit": result.returncode, "started_ns": started, "finished_ns": time.time_ns()})
        commands = json.dumps(receipts, indent=2) + "\n"
        if index == 0:
            directory.create_text("commands.json", commands)
        else:
            directory.replace_text("commands.json", commands)
        return result

    subprocess.run = observed
    try:
        HaproxySpopEventSinkFailureTests.setUpClass()
        # Preserve generated C, compiled current/unsafe binaries and every
        # resulting physical sink after assertions, before normal cleanup.
        stream = io.StringIO()
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(HaproxySpopEventSinkFailureTests)
        # setUpClass already ran under observation; prevent a second build.
        HaproxySpopEventSinkFailureTests.setUpClass = classmethod(lambda cls: None)
        retained = output / "native-artifacts"
        unittest_result = None
        original_cleanup = HaproxySpopEventSinkFailureTests.doClassCleanups

        def retain_and_clean(cls):
            os.fstat(directory.descriptor)
            shutil.copytree(cls.directory, retained)
            os.fstat(directory.descriptor)
            original_cleanup()

        HaproxySpopEventSinkFailureTests.doClassCleanups = classmethod(retain_and_clean)
        unittest_result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        directory.create_text("tests.log", stream.getvalue())
        os.fstat(directory.descriptor)
        files = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in output.rglob("*") if path.is_file()}
        os.fstat(directory.descriptor)
        directory.create_text("receipt.json", json.dumps({"evidence_class": "native-C-physical-stdio",
            "full_lifecycle_pass": False, "tests_run": unittest_result.testsRun,
            "failures": len(unittest_result.failures), "errors": len(unittest_result.errors),
            "files": files}, indent=2) + "\n")
        return 0 if unittest_result.wasSuccessful() else 1
    finally:
        subprocess.run = original


if __name__ == "__main__":
    raise SystemExit(main())
