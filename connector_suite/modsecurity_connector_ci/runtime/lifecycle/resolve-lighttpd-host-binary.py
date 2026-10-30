#!/usr/bin/env python3
"""Resolve the staged Lighttpd binary used only for host-version inventory.

The no-CRS runner must never fall back to a host executable or a mutable
shared-cache path for this metadata. It resolves only the fixed staged
Lighttpd location beneath the current connector build root; inherited
``LIGHTTPD_BIN`` values are deliberately not consumed here.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import stat
import sys




from modsecurity_connector_ci.lib.runtime_path_utils import prepare_verified_runtime_artifact_root, runtime_artifact_path


def resolve_lighttpd_host_binary(build_root: Path) -> Path:
    """Return the exact no-follow staged binary below ``build_root``.

    ``runtime_artifact_path`` rejects relative paths, root escapes, symlinks,
    and non-regular files.  The executable-bit check is deliberately separate
    because a readable regular file is not safe to invoke for version
    collection.
    """

    runtime_root = prepare_verified_runtime_artifact_root(build_root)
    candidate = runtime_root / "lighttpd-connector" / "bin" / "lighttpd"
    target = runtime_artifact_path(
        runtime_root, candidate, "staged Lighttpd binary", must_exist=True
    )
    mode = target.stat(follow_symlinks=False).st_mode
    if not stat.S_ISREG(mode):
        raise ValueError("LIGHTTPD_BIN must be a regular file")
    if not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ValueError("LIGHTTPD_BIN must be executable")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", required=True)
    args = parser.parse_args(argv)
    try:
        target = resolve_lighttpd_host_binary(Path(args.build_root))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
