#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
REPO_ROOT="${REPO_ROOT:-$FRAMEWORK_ROOT}"
. "$CI_ROOT/lib/common.sh"

VENV_DIR="${VENV_DIR:-.venv}"
PYTHON_BIN="${PYTHON_BIN:-$DEFAULT_PYTHON}"
REQ_FILE="${REQ_FILE:-$REPO_ROOT/requirements-dev.txt}"

if [ ! -f "$REQ_FILE" ]; then
    ci_blocked "missing dependency file: $REQ_FILE" >&2
    exit 2
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$REQ_FILE"

ci_info "created virtual environment at $VENV_DIR"
ci_info "hint: source $VENV_DIR/bin/activate"
