#!/usr/bin/env python3
"""Resolve the staged Traefik binary used only for host-version inventory.

The no-CRS runner must never fall back to a host executable or a mutable
shared-cache path for this metadata. It resolves only the fixed staged
Traefik location beneath the current connector build root; inherited
``TRAEFIK_BIN`` values are deliberately not consumed here.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys




from modsecurity_connector_ci.lib.runtime_path_utils import prepare_verified_runtime_artifact_root, runtime_artifact_path


def resolve_traefik_host_binary(build_root: Path) -> Path:
    """Return the exact no-follow staged binary below ``build_root``.

    ``runtime_artifact_path`` rejects relative paths, root escapes, symlinks,
    and non-regular files.  The executable-bit check is deliberately separate
    because a readable regular file is not safe to invoke for version
    collection.
    """

    runtime_root = prepare_verified_runtime_artifact_root(build_root)
    candidate = runtime_root / "traefik-connector" / "bin" / "traefik"
    target = runtime_artifact_path(
        runtime_root, candidate, "staged Traefik binary", must_exist=True
    )
    details = target.stat(follow_symlinks=False)
    mode = details.st_mode
    if details.st_uid != os.geteuid() or details.st_nlink != 1 or stat.S_IMODE(mode) & 0o022:
        raise ValueError("staged Traefik binary must be current-user owned, singly linked and not externally writable")
    if not stat.S_ISREG(mode):
        raise ValueError("TRAEFIK_BIN must be a regular file")
    if not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ValueError("TRAEFIK_BIN must be executable")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", required=True)
    args = parser.parse_args(argv)
    try:
        target = resolve_traefik_host_binary(Path(args.build_root))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
