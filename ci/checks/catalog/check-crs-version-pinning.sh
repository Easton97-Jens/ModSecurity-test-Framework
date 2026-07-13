#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-${REPO_ROOT:-$(pwd)}}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

status=0

check_path() {
    path=$1
    case "$path" in
        ci/lib/common.sh) return 0 ;;
    esac
    if [ -n "$CRS_GIT_REF" ] && grep -nF "$CRS_GIT_REF" "$path" >/tmp/crs-version-pinning.$$ 2>/dev/null; then
        cat /tmp/crs-version-pinning.$$
        ci_error "CRS version literal must be defined only in ci/lib/common.sh: $path"
        status=1
    fi
    if grep -nE 'CRS_GIT_REF[[:space:]]*[:?+]?=' "$path" >/tmp/crs-version-pinning.$$ 2>/dev/null; then
        cat /tmp/crs-version-pinning.$$
        ci_error "CRS_GIT_REF assignment must be defined only in ci/lib/common.sh: $path"
        status=1
    fi
}

trap 'rm -f /tmp/crs-version-pinning.$$' EXIT INT TERM

if [ -f Makefile ]; then
    check_path Makefile
fi
for path in $(find ci -type f -name '*.sh' -print | sort) .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -e "$path" ] || continue
    check_path "$path"
done

exit "$status"
