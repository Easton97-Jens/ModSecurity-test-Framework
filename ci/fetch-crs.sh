#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$FRAMEWORK_ROOT}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"

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
        exit 77
    fi
    ci_info "fetch_crs updating $CRS_SOURCE_DIR ref=$CRS_GIT_REF"
    set +e
    git -C "$CRS_SOURCE_DIR" fetch --depth 1 origin "$CRS_GIT_REF"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        notice "CRS fetch blocked for $CRS_REPO_URL ref=$CRS_GIT_REF"
        exit 77
    fi
    git -C "$CRS_SOURCE_DIR" checkout --detach FETCH_HEAD >/dev/null 2>&1 || {
        ci_blocked "fetch_crs could not checkout CRS ref: $CRS_GIT_REF"
        exit 77
    }
}

clone_crs() {
    if [ -e "$CRS_SOURCE_DIR" ] && [ ! -d "$CRS_SOURCE_DIR/.git" ]; then
        ci_blocked "fetch_crs destination exists but is not a git checkout: $CRS_SOURCE_DIR"
        exit 77
    fi
    if [ -d "$CRS_SOURCE_DIR/.git" ]; then
        checkout_existing_crs
        return 0
    fi
    ci_info "fetch_crs fetching $CRS_REPO_URL ref=$CRS_GIT_REF into $CRS_SOURCE_DIR"
    set +e
    git clone --depth 1 --branch "$CRS_GIT_REF" "$CRS_REPO_URL" "$CRS_SOURCE_DIR"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        notice "CRS clone blocked for $CRS_REPO_URL ref=$CRS_GIT_REF"
        rm -rf "$CRS_SOURCE_DIR"
        exit 77
    fi
}

ci_require_absolute_path "$SOURCE_ROOT" "SOURCE_ROOT" || exit 77
require_fetch_path "$CRS_SOURCE_DIR" "CRS_SOURCE_DIR"
mkdir -p "$SOURCE_ROOT"
clone_crs
ci_info "fetch_crs ready CRS_SOURCE_DIR=$CRS_SOURCE_DIR"
