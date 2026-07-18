#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
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
    check_literal "$path" "$CRS_GIT_REF" CRS_GIT_REF
    check_literal "$path" "$CRS_GIT_COMMIT" CRS_GIT_COMMIT
    if grep -nE 'CRS_GIT_(REF|COMMIT)[[:space:]]*[:?+]?=' "$path" >"$CHECK_OUTPUT" 2>/dev/null; then
        cat "$CHECK_OUTPUT"
        ci_error "CRS source identifier assignments must be defined only in ci/lib/common.sh: $path"
        status=1
    fi
}

trap 'rm -f "$CHECK_OUTPUT"' EXIT INT TERM

ci_require_approved_crs_source || exit 77

if [ -f Makefile ]; then
    check_path Makefile
fi
for path in $(find ci -type f -name '*.sh' -print | sort) .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -e "$path" ] || continue
    check_path "$path"
done

exit "$status"
