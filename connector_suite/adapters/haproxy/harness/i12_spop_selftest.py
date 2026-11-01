#!/usr/bin/env python3
"""Run the fresh native SPOP protocol regression in an admitted private runtime.

This command is not a HAProxy host request and cannot qualify an I12 lifecycle.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    root = Path("/task")
    argv = ["rtk", "proxy", "/mnt/artifacts/haproxy-spop", "--runtime-self-test",
            "--tmp-root", "/task/t", "--log-root", "/task/l"]
    started = time.time_ns()
    with (root / "selftest.stdout").open("wb") as out, (root / "selftest.stderr").open("wb") as err:
        result = subprocess.run(argv, stdout=out, stderr=err, timeout=120)
    files = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in root.rglob("*") if path.is_file()}
    (root / "selftest-receipt.json").write_text(json.dumps({"argv": argv,
        "cwd": os.getcwd(), "exit": result.returncode, "started_ns": started,
        "finished_ns": time.time_ns(), "expected_exit": 0,
        "observation_result": "passed" if result.returncode == 0 else "failed",
        "files": files, "evidence_class": "native-agent-selftest",
        "full_lifecycle_pass": False}, indent=2) + "\n")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
