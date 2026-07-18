#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
SCRIPT_PATH="$SCRIPT_DIR/check-crs-version-pinning.sh"
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-${REPO_ROOT:-$(pwd)}}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

status=0
tmp_file=
path_list=

assert_safe_runtime_path "$TMP_ROOT" "CRS version-pinning temporary directory" || exit 77
if ! mkdir -p "$TMP_ROOT"; then
    ci_error "cannot create CRS version-pinning temporary directory: $TMP_ROOT"
    exit 2
fi
umask 077
tmp_file=$(mktemp "$TMP_ROOT/crs-version-pinning.XXXXXX") || {
    ci_error "cannot create CRS version-pinning temporary file in: $TMP_ROOT"
    exit 2
}
path_list=$(mktemp "$TMP_ROOT/crs-version-pinning-paths.XXXXXX") || {
    ci_error "cannot create CRS version-pinning path list in: $TMP_ROOT"
    exit 2
}

check_path() {
    path=$1
    case "$path" in
        ci/lib/common.sh) return 0 ;;
    esac
    if [ -n "$CRS_GIT_REF" ]; then
        if grep -nF "$CRS_GIT_REF" "$path" >"$tmp_file" 2>/dev/null; then
            cat "$tmp_file"
            ci_error "CRS version literal must be defined only in ci/lib/common.sh: $path"
            status=1
        else
            grep_status=$?
            if [ "$grep_status" -gt 1 ]; then
                ci_error "cannot scan CRS version literals in: $path"
                status=1
            fi
        fi
    fi
    if grep -nE 'CRS_GIT_REF[[:space:]]*[:?+]?=' "$path" >"$tmp_file" 2>/dev/null; then
        cat "$tmp_file"
        ci_error "CRS_GIT_REF assignment must be defined only in ci/lib/common.sh: $path"
        status=1
    else
        grep_status=$?
        if [ "$grep_status" -gt 1 ]; then
            ci_error "cannot scan CRS_GIT_REF assignments in: $path"
            status=1
        fi
    fi
}

trap 'rm -f -- "$tmp_file" "$path_list"' EXIT HUP INT TERM

if [ "${1:-}" = "--check-path" ]; then
    if [ "$#" -ne 2 ]; then
        ci_error "usage: $0 --check-path <path>"
        exit 2
    fi
    check_path "$2"
    exit "$status"
fi

if [ "$#" -ne 0 ]; then
    ci_error "usage: $0"
    exit 2
fi

if [ -f Makefile ]; then
    check_path Makefile
fi
if ! find ci -type f -name '*.sh' -print0 >"$path_list"; then
    ci_error "cannot enumerate shell files for CRS version-pinning checks"
    status=1
elif ! xargs -0 -r -n 1 sh "$SCRIPT_PATH" --check-path <"$path_list"; then
    ci_error "CRS version-pinning check failed in shell files"
    status=1
fi

for path in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -e "$path" ] || continue
    check_path "$path"
done

exit "$status"
