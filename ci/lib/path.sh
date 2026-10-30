#!/bin/sh
# Source-only explicit Framework path selection. The working directory and
# Connector nesting never choose a checkout or helper.

ci_find_framework_root() {
    if [ -z "${TEST_ROOT:-}" ]; then
        printf '%s\n' "framework CI: TEST_ROOT is required explicitly" >&2
        return 2
    fi
    case "$TEST_ROOT" in
        /*) ;;
        *) printf '%s\n' "framework CI: TEST_ROOT must be absolute" >&2; return 2 ;;
    esac
    ci_selected_root=$(CDPATH= cd -- "$TEST_ROOT" && pwd -P) || return 2
    if [ ! -f "$ci_selected_root/modsecurity_test_framework/__init__.py" ]; then
        printf '%s\n' "framework CI: TEST_ROOT lacks the Framework package anchor" >&2
        return 2
    fi
    printf '%s\n' "$ci_selected_root"
}

ci_init_paths() {
    FRAMEWORK_ROOT=$(ci_find_framework_root "$1") || return 2
    TEST_ROOT=$FRAMEWORK_ROOT
    CI_ROOT="$TEST_ROOT/ci"
    if [ ! -d "$CI_ROOT" ]; then
        printf '%s\n' "framework CI: CI_ROOT is not a directory: $CI_ROOT" >&2
        return 2
    fi
    PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
    PYTHONSAFEPATH=1
    PYTHONNOUSERSITE=1
    export TEST_ROOT FRAMEWORK_ROOT CI_ROOT PYTHONPATH PYTHONSAFEPATH PYTHONNOUSERSITE
}

ci_source_path_helper() {
    ci_selected_root=$(ci_find_framework_root "$1") || return 2
    # shellcheck source=ci/lib/path.sh
    . "$ci_selected_root/ci/lib/path.sh"
}
