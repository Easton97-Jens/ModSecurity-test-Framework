#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"

RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export PYTHONDONTWRITEBYTECODE

mkdir -p "$RESULTS_DIR"

run_connector() {
    name=$1
    script=$2
    echo "run_connector_smokes: running $name"
    set +e
    FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$script"
    rc=$?
    set -e
    printf '%s\n' "$rc" > "$RESULTS_DIR/$name.rc"
}

run_connector apache "$FRAMEWORK_ROOT/ci/run-apache-smoke.sh"
run_connector nginx "$FRAMEWORK_ROOT/ci/run-nginx-smoke.sh"

{
    echo "[apache]"
    if [ -f "$RESULTS_DIR/apache-summary.txt" ]; then
        cat "$RESULTS_DIR/apache-summary.txt"
    else
        echo "BLOCKED apache-summary missing"
    fi
    echo
    echo "[nginx]"
    if [ -f "$RESULTS_DIR/nginx-summary.txt" ]; then
        cat "$RESULTS_DIR/nginx-summary.txt"
    else
        echo "BLOCKED nginx-summary missing"
    fi
} > "$RESULTS_DIR/connector-summary.txt"

"$(ci_python)" - "$RESULTS_DIR" <<'PY'
import json
import sys
from pathlib import Path

results_dir = Path(sys.argv[1])
combined = {}
for name in ("apache", "nginx"):
    path = results_dir / f"{name}-summary.json"
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            combined.update(json.load(handle))
    else:
        combined[name] = {"summary": "blocked"}
with (results_dir / "connector-summary.json").open("w", encoding="utf-8") as handle:
    json.dump(combined, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

apache_rc=$(cat "$RESULTS_DIR/apache.rc")
nginx_rc=$(cat "$RESULTS_DIR/nginx.rc")

if [ "$apache_rc" -ne 0 ] && [ "$apache_rc" -ne 77 ]; then
    exit 1
fi
if [ "$nginx_rc" -ne 0 ] && [ "$nginx_rc" -ne 77 ]; then
    exit 1
fi
if [ "$apache_rc" -eq 77 ] || [ "$nginx_rc" -eq 77 ]; then
    exit 77
fi
exit 0
