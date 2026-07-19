#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../../lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-${REPO_ROOT:-$(pwd)}}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

status=0
ci_require_absolute_path "$TMP_ROOT" TMP_ROOT || exit 77
assert_safe_runtime_path "$TMP_ROOT" TMP_ROOT || exit 77
mkdir -p "$TMP_ROOT"
CHECK_OUTPUT=$(mktemp "$TMP_ROOT/crs-version-pinning.XXXXXX")

check_literal() {
    path=$1
    literal=$2
    variable=$3
    if [ -n "$literal" ] && grep -nF "$literal" "$path" >"$CHECK_OUTPUT" 2>/dev/null; then
        cat "$CHECK_OUTPUT"
        ci_error "$variable literal must be defined only in ci/lib/common.sh: $path"
        status=1
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
    if grep -nE 'CRS_(APPROVED_REPO_URL|APPROVED_COMMIT|RELEASE_TAG|REPO_URL|GIT_REF)[[:space:]]*[:?+]?=' "$path" >"$CHECK_OUTPUT" 2>/dev/null; then
        cat "$CHECK_OUTPUT"
        ci_error "CRS provenance assignments must be defined only in ci/lib/common.sh: $path"
        status=1
    fi
}

trap 'rm -f "$CHECK_OUTPUT"' EXIT INT TERM

if [ "${1:-}" = "--check-paths" ]; then
    check_status=${2:-}
    if [ -z "$check_status" ]; then
        ci_error "internal CRS path-check status file is required"
        exit 77
    fi
    shift 2
    for path do
        check_path "$path"
    done
    if [ "$status" -ne 0 ]; then
        printf '%s\n' failure >"$check_status"
    fi
    exit "$status"
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
: >"$CHECK_OUTPUT"
if ! find ci -type f -name '*.sh' -exec sh "$0" --check-paths "$CHECK_OUTPUT" {} +; then
    status=1
fi
if [ -s "$CHECK_OUTPUT" ]; then
    status=1
fi
for path in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -e "$path" ] || continue
    check_path "$path"
done

exit "$status"
