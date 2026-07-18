#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$FRAMEWORK_ROOT}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

notice() {
    message=$1
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::notice::$message"
    else
        ci_info "fetch_crs $message"
    fi
}

require_fetch_path() {
    path=$1
    label=$2
    ci_require_absolute_path "$path" "$label" || exit 77
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$SOURCE_ROOT"|"$SOURCE_ROOT"/*) ;;
        *)
            ci_blocked "fetch_crs $label must be under SOURCE_ROOT: $path"
            exit 77
            ;;
    esac
}

checkout_existing_crs() {
    remote_url=$(git -C "$CRS_SOURCE_DIR" config --get remote.origin.url 2>/dev/null || true)
    if [ "$remote_url" != "$CRS_REPO_URL" ]; then
        ci_blocked "fetch_crs existing CRS checkout has unexpected origin: $remote_url"
        ci_blocked "fetch_crs expected origin: $CRS_REPO_URL"
        return 77
    fi
    ci_info "fetch_crs updating $CRS_SOURCE_DIR commit=$CRS_GIT_COMMIT release=$CRS_GIT_REF"
    set +e
    git -C "$CRS_SOURCE_DIR" fetch --depth 1 origin "$CRS_GIT_COMMIT"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        notice "CRS fetch blocked for $CRS_REPO_URL commit=$CRS_GIT_COMMIT"
        return 77
    fi
    git -C "$CRS_SOURCE_DIR" checkout --detach "$CRS_GIT_COMMIT" >/dev/null 2>&1 || {
        ci_blocked "fetch_crs could not checkout CRS commit: $CRS_GIT_COMMIT"
        return 77
    }
    actual_commit=$(git -C "$CRS_SOURCE_DIR" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)
    if [ "$actual_commit" != "$CRS_GIT_COMMIT" ]; then
        ci_blocked "fetch_crs checked-out CRS commit does not match the approved commit"
        return 77
    fi
    git -C "$CRS_SOURCE_DIR" submodule sync --recursive >/dev/null 2>&1 || true
    git -C "$CRS_SOURCE_DIR" submodule update --init --recursive || {
        ci_blocked "fetch_crs submodule update failed"
        return 77
    }
    return 0
}

clone_crs() {
    if [ -e "$CRS_SOURCE_DIR" ] && [ ! -d "$CRS_SOURCE_DIR/.git" ]; then
        ci_blocked "fetch_crs destination exists but is not a git checkout: $CRS_SOURCE_DIR"
        exit 77
    fi
    if [ -d "$CRS_SOURCE_DIR/.git" ]; then
        checkout_existing_crs || exit 77
        return 0
    fi
    ci_info "fetch_crs fetching $CRS_REPO_URL commit=$CRS_GIT_COMMIT release=$CRS_GIT_REF into $CRS_SOURCE_DIR"
    set +e
    git init "$CRS_SOURCE_DIR" >/dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        notice "CRS checkout initialization blocked for $CRS_REPO_URL"
        safe_remove_runtime_path "$CRS_SOURCE_DIR" "$SOURCE_ROOT" "failed CRS checkout initialization" || true
        exit 77
    fi
    git -C "$CRS_SOURCE_DIR" remote add origin "$CRS_REPO_URL" >/dev/null 2>&1 || {
        ci_blocked "fetch_crs could not configure the approved CRS origin"
        safe_remove_runtime_path "$CRS_SOURCE_DIR" "$SOURCE_ROOT" "failed CRS origin configuration" || true
        exit 77
    }
    checkout_existing_crs || {
        safe_remove_runtime_path "$CRS_SOURCE_DIR" "$SOURCE_ROOT" "failed CRS checkout"
        exit 77
    }
}

ci_require_absolute_path "$SOURCE_ROOT" "SOURCE_ROOT" || exit 77
ci_require_approved_crs_source || exit 77
ci_require_https_github_repo_url "$CRS_REPO_URL" "CRS_REPO_URL" || exit 77
assert_safe_runtime_path "$SOURCE_ROOT" SOURCE_ROOT || exit 77
require_fetch_path "$CRS_SOURCE_DIR" "CRS_SOURCE_DIR"
mkdir -p "$SOURCE_ROOT"
clone_crs
ci_info "fetch_crs ready CRS_SOURCE_DIR=$CRS_SOURCE_DIR"
