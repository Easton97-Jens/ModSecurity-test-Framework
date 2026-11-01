"""Run wildcard-listener negative tests in a verified private network namespace."""

from __future__ import annotations

from functools import wraps
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys


_PARENT_NAMESPACE = "FRAMEWORK_WILDCARD_TEST_PARENT_NETNS"
_SELECTED_TEST = "FRAMEWORK_WILDCARD_TEST_ID"
_CHILD_RUNNER = """
import sys, unittest
suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful():
    sys.exit(1)
sys.exit(77 if result.skipped else 0)
"""


def private_network_test(method):
    """Require real namespace isolation before executing a wildcard socket test.

    The namespace must differ from the invoking parent's and contain only lo.
    Neither an environment marker nor a successful launcher alone grants entry.
    Missing namespace support is an explicit unittest skip, never a socket PASS.
    """

    @wraps(method)
    def isolated(self):
        namespace_path = Path("/proc/self/ns/net")
        if not namespace_path.exists():
            self.skipTest("BLOCKED: Linux network namespaces are unavailable")
        current_namespace = os.readlink(namespace_path)
        selected = os.environ.get(_SELECTED_TEST)
        if selected == self.id():
            parent_namespace = os.environ.get(_PARENT_NAMESPACE)
            self.assertIsNotNone(parent_namespace, "missing invoking parent namespace identity")
            self.assertNotEqual(current_namespace, parent_namespace)
            self.assertEqual({name for _, name in socket.if_nameindex()}, {"lo"})
            return method(self)

        unshare = shutil.which("unshare")
        if unshare is None:
            self.skipTest("BLOCKED: unshare is required for wildcard-listener isolation")
        command = [unshare, "--user", "--map-root-user", "--net"]
        prerequisite = subprocess.run(
            [*command, sys.executable, "-c", "pass"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if prerequisite.returncode:
            self.skipTest("BLOCKED: private user/network namespace setup is unavailable")
        environment = os.environ.copy()
        environment[_PARENT_NAMESPACE] = current_namespace
        environment[_SELECTED_TEST] = self.id()
        child = subprocess.run(
            [*command, sys.executable, "-c", _CHILD_RUNNER, self.id()],
            env=environment, capture_output=True, text=True, timeout=30, check=False,
        )
        if child.returncode == 77:
            self.skipTest("BLOCKED: isolated wildcard-listener prerequisite unavailable\n" + child.stderr)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)

    return isolated
