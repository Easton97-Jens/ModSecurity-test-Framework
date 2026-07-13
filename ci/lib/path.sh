#!/bin/sh
# Shared, source-only path discovery for Framework CI entrypoints.
#
# Every direct CI entrypoint first discovers ci/lib/path.sh from its own
# directory, then calls ci_init_paths.  Keeping discovery here means moving a
# script between CI responsibility folders does not change its runtime roots.

ci_find_framework_root() {
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

ci_init_paths() {
    script_dir=$1
    if [ -z "${FRAMEWORK_ROOT:-}" ]; then
        FRAMEWORK_ROOT=$(ci_find_framework_root "$script_dir") || {
            printf '%s\n' "framework CI: unable to discover FRAMEWORK_ROOT from $script_dir" >&2
            return 2
        }
    fi
    FRAMEWORK_ROOT=$(CDPATH= cd -- "$FRAMEWORK_ROOT" && pwd)
    CI_ROOT="${CI_ROOT:-$FRAMEWORK_ROOT/ci}"
    if [ ! -d "$CI_ROOT" ]; then
        printf '%s\n' "framework CI: CI_ROOT is not a directory: $CI_ROOT" >&2
        return 2
    fi
    export FRAMEWORK_ROOT CI_ROOT
}

ci_source_path_helper() {
    script_dir=$1
    search_dir=$script_dir
    while [ "$search_dir" != "/" ]; do
        if [ -f "$search_dir/lib/path.sh" ]; then
            # shellcheck source=ci/lib/path.sh
            . "$search_dir/lib/path.sh"
            return 0
        fi
        search_dir=$(dirname "$search_dir")
    done
    printf '%s\n' "framework CI: unable to locate ci/lib/path.sh from $script_dir" >&2
    return 2
}
