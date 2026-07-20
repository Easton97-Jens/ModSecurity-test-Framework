#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
SCRIPT_PATH="$SCRIPT_DIR/check-crs-version-pinning.sh"
. "$SCRIPT_DIR/../../lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-${REPO_ROOT:-$(pwd)}}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

status=0
tmp_file=
path_list=

ci_require_absolute_path "$TMP_ROOT" TMP_ROOT || exit 77
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

check_literal() {
    path=$1
    literal=$2
    variable=$3
    if [ -n "$literal" ]; then
        if grep -nF "$literal" "$path" >"$tmp_file" 2>/dev/null; then
            cat "$tmp_file"
            ci_error "$variable literal must be defined only in ci/lib/common.sh: $path"
            status=1
        else
            grep_status=$?
            if [ "$grep_status" -gt 1 ]; then
                ci_error "cannot scan $variable literal in: $path"
                status=1
            fi
        fi
    fi
}

check_path() {
    path=$1
    case "$path" in
        ci/lib/common.sh) return 0 ;;
    esac
    check_literal "$path" "$CRS_APPROVED_REPO_URL" CRS_APPROVED_REPO_URL
    check_literal "$path" "$CRS_APPROVED_COMMIT" CRS_APPROVED_COMMIT
    check_literal "$path" "$CRS_RELEASE_TAG" CRS_RELEASE_TAG
    if grep -nE 'CRS_(APPROVED_REPO_URL|APPROVED_COMMIT|RELEASE_TAG|REPO_URL|GIT_REF)[[:space:]]*[:?+]?=' "$path" >"$tmp_file" 2>/dev/null; then
        cat "$tmp_file"
        ci_error "CRS provenance assignments must be defined only in ci/lib/common.sh: $path"
        status=1
    else
        grep_status=$?
        if [ "$grep_status" -gt 1 ]; then
            ci_error "cannot scan CRS provenance assignments in: $path"
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

ci_require_https_github_repo_url "$CRS_APPROVED_REPO_URL" CRS_APPROVED_REPO_URL || exit 77
ci_require_full_git_commit "$CRS_APPROVED_COMMIT" CRS_APPROVED_COMMIT || exit 77
if [ "$CRS_REPO_URL" != "$CRS_APPROVED_REPO_URL" ]; then
    ci_error "CRS_REPO_URL must equal the approved CRS origin"
    exit 77
fi
if [ "$CRS_GIT_REF" != "$CRS_RELEASE_TAG" ]; then
    ci_error "CRS_GIT_REF must remain release metadata and equal CRS_RELEASE_TAG"
    exit 77
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
