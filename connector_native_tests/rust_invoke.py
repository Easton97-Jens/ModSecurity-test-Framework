"""Framework-owned adapter for Rust Cargo workspace tests."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess


def main() -> int:
    connector = Path(os.environ.get("CONNECTOR_ROOT", "")).resolve()
    revision = os.environ.get("CONNECTOR_REVISION", "").strip()
    if not connector.is_dir():
        raise SystemExit("CONNECTOR_ROOT must name an existing connector checkout")
    if len(revision) != 40:
        raise SystemExit("CONNECTOR_REVISION must be the exact 40-character Git SHA")

    actual = subprocess.run(
        ["git", "-C", str(connector), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual != revision:
        raise SystemExit("Connector checkout HEAD does not match CONNECTOR_REVISION")

    manifest = connector / "rust" / "Cargo.toml"
    if not manifest.is_file():
        raise SystemExit("Connector Rust workspace manifest is missing")

    return subprocess.run(
        ["cargo", "test", "--workspace", "--locked", "--manifest-path", str(manifest)],
        cwd=str(connector),
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
