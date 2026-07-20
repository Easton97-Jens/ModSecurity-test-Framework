#!/bin/sh
# Source after a direct CI entrypoint has derived SCRIPT_DIR from its own $0.
# Inherited CI_ROOT and FRAMEWORK_ROOT values are intentionally ignored: they
# cannot be trusted to choose a helper before this bootstrap runs.

if [ -z "${SCRIPT_DIR:-}" ]; then
    printf '%s\n' "framework CI: SCRIPT_DIR is required before path bootstrap" >&2
    return 2 2>/dev/null || exit 2
fi

ci_path_bootstrap_find_framework_root() {
    search_dir=$1
    while [ "$search_dir" != "/" ]; do
        if [ -f "$search_dir/Makefile" ] && [ -d "$search_dir/ci" ] && [ -d "$search_dir/tests" ]; then
            printf '%s\n' "$search_dir"
            return 0
        fi
        search_dir=$(dirname "$search_dir")
    done
    return 1
}

if ! FRAMEWORK_ROOT=$(ci_path_bootstrap_find_framework_root "$SCRIPT_DIR"); then
    printf '%s\n' "framework CI: unable to derive FRAMEWORK_ROOT from SCRIPT_DIR: $SCRIPT_DIR" >&2
    return 2 2>/dev/null || exit 2
fi
if ! FRAMEWORK_ROOT=$(CDPATH= cd -- "$FRAMEWORK_ROOT" && pwd); then
    printf '%s\n' "framework CI: unable to canonicalize FRAMEWORK_ROOT" >&2
    return 2 2>/dev/null || exit 2
fi
CI_ROOT="$FRAMEWORK_ROOT/ci"
if [ ! -f "$CI_ROOT/lib/path.sh" ]; then
    printf '%s\n' "framework CI: missing path helper under derived CI_ROOT: $CI_ROOT" >&2
    return 2 2>/dev/null || exit 2
fi

# shellcheck source=ci/lib/path.sh
. "$CI_ROOT/lib/path.sh"

# ci_init_paths performs its normal final validation using only the roots
# derived above, never inherited values from the caller environment.
if ! ci_init_paths "$SCRIPT_DIR"; then
    return 2 2>/dev/null || exit 2
fi
if [ "$CI_ROOT" != "$FRAMEWORK_ROOT/ci" ]; then
    printf '%s\n' "framework CI: derived CI_ROOT does not match FRAMEWORK_ROOT: $CI_ROOT" >&2
    return 2 2>/dev/null || exit 2
fi

export FRAMEWORK_ROOT CI_ROOT
