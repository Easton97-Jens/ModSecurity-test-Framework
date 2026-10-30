#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
PYTHON_BIN="${PYTHON:-python3}"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    echo "BLOCKED: missing Python interpreter for Traefik runtime harness: $PYTHON_BIN" >&2
    exit 77
}

exec "$PYTHON_BIN" -P "$SCRIPT_DIR/runtime_smoke.py" "$@"
