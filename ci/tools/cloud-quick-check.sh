#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

PYTHON_BIN="${PYTHON_BIN:-}"
status=0

run_required() {
  label=$1
  shift
  ci_info "cloud-quick-check running $label"
  if "$@"; then
    ci_info "cloud-quick-check PASS $label"
    return
  fi
  rc=$?
  ci_error "cloud-quick-check FAIL $label (exit=$rc)"
  status=1
}

run_required "make setup-dev" make setup-dev
PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"
run_required "make lint" make lint
run_required "make refresh-framework-reports" make refresh-framework-reports
run_required "make check-test-matrix" make check-test-matrix
run_required "make quick-check" make quick-check
run_required "$PYTHON_BIN -m py_compile framework tests/runners, tests/normalizers, ci" \
  "$PYTHON_BIN" -m py_compile "$FRAMEWORK_ROOT"/tests/normalizers/*.py "$FRAMEWORK_ROOT"/tests/runners/*.py $(find "$FRAMEWORK_ROOT/ci" -type f -name '*.py' -print | sort)
run_required "git diff --check" git diff --check

if [ "$status" -eq 0 ]; then
  ci_info "Cloud check is framework/generator only and not runtime compatibility evidence."
else
  ci_error "cloud-quick-check FAIL"
fi

exit "$status"
