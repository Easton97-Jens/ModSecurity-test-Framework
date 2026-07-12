#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
REPO_ROOT="${REPO_ROOT:-$FRAMEWORK_ROOT}"
. "$CI_ROOT/lib/common.sh"

PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"

"$PYTHON_BIN" "$REPO_ROOT/ci/lib/adapter_metadata.py" check-drift
