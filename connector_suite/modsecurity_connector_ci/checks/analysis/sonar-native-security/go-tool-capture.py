#!/usr/bin/env python3
"""Execute Go's actual tool unchanged; retain link output after FIPS finalization."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    if len(sys.argv) < 2:
        return 2
    command = sys.argv[1:]
    status = subprocess.run(command, check=False).returncode
    if status or Path(command[0]).name != "link" or "-o" not in command:
        return status
    try:
        root = Path(os.environ["SONAR_NATIVE_CAPTURE_ROOT"]).resolve(strict=True)
        if root.stat().st_mode & 0o077:
            raise ValueError("Go link capture root must be private")
        output = Path(command[command.index("-o") + 1]).resolve(strict=True)
        identifier = uuid.uuid4().hex
        retained = root / "go-postlink" / identifier
        retained.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(output, retained)
        if digest(output) != digest(retained):
            raise ValueError("Go linker output changed during retention")
        record = {"schema": 1, "kind": "go-tool-link", "arguments": command,
                  "tool_sha256": digest(command[0]), "directory": str(Path.cwd().resolve()),
                  "output": str(output), "output_sha256": digest(output),
                  "retained_output": str(retained)}
        (root / (identifier + ".json")).write_text(json.dumps(record, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError) as error:
        print(f"Go linker retention failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
