"""Share default admission and explicit specialist Go overlay invocation."""
from __future__ import annotations

import os
import subprocess
import sys

from modsecurity_test_framework.connector_context import ConnectorContext


MODULES = frozenset({"connectors/envoy/ext_proc", "connectors/traefik/native_middleware",
                     "connectors/traefik/response_observer", "connectors/traefik/composite_middleware"})


def main() -> int:
    context = ConnectorContext.from_environment()
    module = os.environ.get("GO_TEST_MODULE", "")
    if module not in MODULES:
        raise ValueError("GO_TEST_MODULE must name one fixed connector module")
    base = [sys.executable, "-P", "-m", "modsecurity_test_framework.connector",
            "--connector-root", str(context.connector), "--connector-revision", context.revision,
            "--test-root", str(context.tests), "--profile", context.profile,
            "--output-root", str(context.output)]
    if os.environ.get("ON_DEMAND_TESTS") != "1":
        return subprocess.run([*base, "--module", module], check=False).returncode
    overlay = subprocess.run([*base, "--emit-go-overlay", module, "--on-demand"],
                             check=True, capture_output=True, text=True).stdout.strip()
    if not overlay.startswith("/") or "\n" in overlay:
        raise ValueError("Framework must return one absolute Go overlay path")
    return subprocess.run(["go", "test", "-mod=readonly", "-count=1", "-overlay", overlay, "./..."],
                          cwd=context.connector / module, check=False,
                          env=dict(os.environ, GOTOOLCHAIN="local")).returncode


if __name__ == "__main__":
    raise SystemExit(main())
