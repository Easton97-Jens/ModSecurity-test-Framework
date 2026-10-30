#!/bin/sh
# Source after a direct CI entrypoint has derived SCRIPT_DIR from its own $0.
# TEST_ROOT selects the Framework checkout; ambient cwd and Parent nesting
# never select sources. Inherited CI_ROOT and FRAMEWORK_ROOT are ignored.

if [ -z "${SCRIPT_DIR:-}" ]; then
    printf '%s\n' "framework CI: SCRIPT_DIR is required before path bootstrap" >&2
    return 2 2>/dev/null || exit 2
fi

# The selected checkout is an explicit input, independent of the working
# directory and the Connector checkout's physical location.
if [ -z "${TEST_ROOT:-}" ]; then
    printf '%s\n' "framework CI: TEST_ROOT is required explicitly" >&2
    return 2 2>/dev/null || exit 2
fi
case "$TEST_ROOT" in
    /*) ;;
    *) printf '%s\n' "framework CI: TEST_ROOT must be absolute" >&2; return 2 2>/dev/null || exit 2 ;;
esac
if ! FRAMEWORK_ROOT=$(CDPATH= cd -- "$TEST_ROOT" && pwd -P); then
    printf '%s\n' "framework CI: unable to canonicalize TEST_ROOT: $TEST_ROOT" >&2
    return 2 2>/dev/null || exit 2
fi
if [ ! -f "$FRAMEWORK_ROOT/modsecurity_test_framework/__init__.py" ]; then
    printf '%s\n' "framework CI: TEST_ROOT lacks the Framework package anchor" >&2
    return 2 2>/dev/null || exit 2
fi
TEST_ROOT=$FRAMEWORK_ROOT
PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
PYTHONSAFEPATH=1
PYTHONNOUSERSITE=1
export TEST_ROOT PYTHONPATH PYTHONSAFEPATH PYTHONNOUSERSITE
CI_ROOT="$FRAMEWORK_ROOT/ci"
if [ ! -f "$CI_ROOT/lib/path.sh" ]; then
    printf '%s\n' "framework CI: missing path helper under derived CI_ROOT: $CI_ROOT" >&2
    return 2 2>/dev/null || exit 2
fi

# shellcheck source=ci/lib/path.sh
. "$CI_ROOT/lib/path.sh"

# ci_init_paths performs its final validation using the explicit selected root.
if ! ci_init_paths "$SCRIPT_DIR"; then
    return 2 2>/dev/null || exit 2
fi
if [ "$CI_ROOT" != "$FRAMEWORK_ROOT/ci" ]; then
    printf '%s\n' "framework CI: derived CI_ROOT does not match FRAMEWORK_ROOT: $CI_ROOT" >&2
    return 2 2>/dev/null || exit 2
fi

export FRAMEWORK_ROOT CI_ROOT
