#!/usr/bin/env python3
"""Run a subprocess with a timeout and print a compact JSON result."""
from __future__ import annotations
import argparse
import json
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        print(json.dumps({"status": "error", "message": "command required"}))
        return 2
    try:
        result = subprocess.run(command, shell=False, check=False, timeout=args.timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(json.dumps({"status": "ok", "returncode": result.returncode, "stdout_size": len(result.stdout), "stderr_size": len(result.stderr)}))
        return result.returncode
    except subprocess.TimeoutExpired:
        print(json.dumps({"status": "timeout", "returncode": None}))
        return 124
    except OSError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
