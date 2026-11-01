"""One fixed environment-to-argv adapter for component native self-tests."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from modsecurity_test_framework.connector_context import ConnectorContext


def main() -> int:
    context = ConnectorContext.from_environment()
    target = os.environ.get("NATIVE_TEST_TARGET", "")
    if not target:
        raise ValueError("NATIVE_TEST_TARGET is required")
    command = [sys.executable, "-P", str(context.tests / "connector_native_tests/run.py"),
               "--connector-root", str(context.connector),
               "--connector-revision", context.revision,
               "--test-root", str(context.tests / "connector_native_tests"),
               "--profile", "native-selftest", "--target", target,
               "--output-root", str(context.output)]
    mode = os.environ.get("NATIVE_TEST_MODE", "")
    if mode:
        if mode not in {"binding", "crs"}:
            raise ValueError("NATIVE_TEST_MODE must be binding or crs")
        rules = Path(os.environ.get("NATIVE_TEST_RULES_FILE", ""))
        if not rules.is_absolute() or not rules.is_file():
            raise ValueError("NATIVE_TEST_RULES_FILE must be an explicit existing rules file")
        command.extend(["--argument=" + ("--self-test" if mode == "binding" else "--self-test-crs"),
                        "--argument=" + str(rules)])
    socket_parent = os.environ.get("TRAEFIK_ENGINE_SOCKET_TEST_PARENT", "")
    if socket_parent:
        command.extend(["--socket-parent", socket_parent])
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
