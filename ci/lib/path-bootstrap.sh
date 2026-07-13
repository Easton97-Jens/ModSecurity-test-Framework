#!/bin/sh
# Source after setting SCRIPT_DIR and CI_ROOT in a direct CI shell entrypoint.

if [ -z "${SCRIPT_DIR:-}" ] || [ -z "${CI_ROOT:-}" ]; then
    printf '%s\n' "framework CI: SCRIPT_DIR and CI_ROOT are required before path bootstrap" >&2
    return 2 2>/dev/null || exit 2
fi

# shellcheck source=ci/lib/path.sh
. "$CI_ROOT/lib/path.sh"
ci_init_paths "$SCRIPT_DIR"
