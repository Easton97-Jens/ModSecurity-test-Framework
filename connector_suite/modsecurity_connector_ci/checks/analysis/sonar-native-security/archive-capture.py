#!/usr/bin/env python3
"""Capture a real deterministic native ar rcs producer and object identities.

Archive records are build evidence; target export additionally needs complete
linker-selected member validation. This helper never fabricates compiler rows.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archiver", required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    try:
        if len(arguments) < 3 or arguments[0] not in {"rcs", "-rcs"}:
            raise ValueError("only the admitted native ar rcs producer is supported")
        archiver = shutil.which(args.archiver)
        if archiver is None:
            raise ValueError("real archiver is unavailable")
        archiver = str(Path(archiver).resolve())
        root = Path(os.environ["SONAR_NATIVE_CAPTURE_ROOT"]).resolve(strict=True)
        if root.stat().st_mode & 0o077:
            raise ValueError("capture root must be private")
        cwd = Path.cwd().resolve()
        output = Path(arguments[1]).resolve()
        inputs = [Path(name).resolve(strict=True) for name in arguments[2:]]
        if any(path.suffix != ".o" for path in inputs) or len({path.name for path in inputs}) != len(inputs):
            raise ValueError("archive requires uniquely named real object inputs")
        before = {str(path): digest(path) for path in inputs}
        command = [archiver, *arguments]
        subprocess.run(command, check=True)
        members = subprocess.check_output([archiver, "t", str(output)], text=True).splitlines()
        if members != [path.name for path in inputs]:
            raise ValueError("real archive member table disagrees with declared inputs")
        for path in inputs:
            content = subprocess.check_output([archiver, "p", str(output), path.name])
            if hashlib.sha256(content).hexdigest() != before[str(path)] or digest(path) != before[str(path)]:
                raise ValueError("archive member bytes disagree with compiler object")
        record = {"schema": 1, "kind": "archive", "directory": str(cwd),
                  "arguments": command, "expanded_arguments": command,
                  "compiler_sha256": digest(Path(archiver)), "sources": {}, "dependencies": {},
                  "response_files": {}, "inputs": before, "linker_inputs": {}, "link_map": {},
                  "members": {path.name: str(path) for path in inputs},
                  "output": str(output), "output_sha256": digest(output)}
        (root / (uuid.uuid4().hex + ".json")).write_text(json.dumps(record, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"native archive capture failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
