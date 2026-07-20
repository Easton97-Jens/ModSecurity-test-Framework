#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$FRAMEWORK_ROOT}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

# Priority order:
# 1) explicit/canonical ModSecurity source aliases when valid
# 2) fetched checkout under SOURCE_ROOT
#
# No sibling workspace or local parent-directory fallback is used here. Missing
# sources should be remediated with MODSECURITY_SOURCE_DIR/MODSECURITY_V3_SOURCE_DIR
# or by running make fetch-deps with the intended BUILD_ROOT/SOURCE_ROOT.

for candidate in \
    "${MODSECURITY_SOURCE_DIR:-}" \
    "${MODSECURITY_V3_SOURCE_DIR:-}" \
    "${MODSECURITY_V3_ROOT:-}" \
    "$SOURCE_ROOT/ModSecurity_V3"
do
    [ -n "$candidate" ] || continue
    if [ -d "$candidate" ]; then
        printf '%s\n' "$candidate"
        exit 0
    fi
done

exit 1
