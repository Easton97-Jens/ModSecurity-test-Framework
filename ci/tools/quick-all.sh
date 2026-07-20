#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"

status=0

run_pass_fail() {
  label=$1
  shift
  ci_info "quick-all running $label"
  if "$@"; then
    ci_info "quick-all PASS $label"
    return 0
  fi
  rc=$?
  ci_error "quick-all FAIL $label (exit=$rc)"
  status=1
  return 0
}

run_blockable() {
  label=$1
  shift
  ci_info "quick-all running $label"
  set +e
  "$@"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    ci_info "quick-all PASS $label"
    return 0
  fi
  if [ "$rc" -eq 77 ]; then
    ci_blocked "quick-all $label (exit=77)"
    [ "$status" -eq 1 ] || status=77
    return 0
  fi
  ci_error "quick-all FAIL $label (exit=$rc)"
  status=1
  return 0
}

run_pass_fail "make lint" make lint
run_blockable "make doctor-quick" make doctor-quick
run_pass_fail "make quick-check" make quick-check
run_blockable "framework smoke-installed" sh "$FRAMEWORK_ROOT/ci/runtime/smoke-installed.sh"
run_pass_fail "$PYTHON_BIN -m py_compile framework tests/runners, tests/normalizers, ci" \
  "$PYTHON_BIN" -m py_compile "$FRAMEWORK_ROOT"/tests/normalizers/*.py "$FRAMEWORK_ROOT"/tests/runners/*.py $(find "$FRAMEWORK_ROOT/ci" -type f -name '*.py' -print | sort)
run_pass_fail "git diff --check" git diff --check

if [ "$status" -eq 0 ]; then
  ci_info "quick-all QUICK PASS"
elif [ "$status" -eq 77 ]; then
  ci_blocked "quick-all QUICK BLOCKED"
else
  ci_error "quick-all QUICK FAIL"
fi

exit "$status"
