#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
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

require_approved_crs_provenance() {
    ci_require_https_github_repo_url "$CRS_APPROVED_REPO_URL" "CRS_APPROVED_REPO_URL" || exit 77
    ci_require_full_git_commit "$CRS_APPROVED_COMMIT" "CRS_APPROVED_COMMIT" || exit 77
    if [ "$CRS_REPO_URL" != "$CRS_APPROVED_REPO_URL" ]; then
        ci_blocked "fetch_crs CRS_REPO_URL override is not permitted: $CRS_REPO_URL"
        exit 77
    fi
    if [ "$CRS_GIT_REF" != "$CRS_RELEASE_TAG" ]; then
        ci_blocked "fetch_crs CRS_GIT_REF is release metadata and cannot select a Git object: $CRS_GIT_REF"
        exit 77
    fi
}

crs_git() (
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
    unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_EXEC_PATH
    unset GIT_TEMPLATE_DIR GIT_PROXY_COMMAND GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL
    unset GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
    unset GIT_SSL_NO_VERIFY GIT_SSL_CAINFO GIT_SSL_CAPATH GIT_ASKPASS SSH_ASKPASS
    unset GIT_SSH GIT_SSH_COMMAND
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_COUNT=0 \
    GIT_TERMINAL_PROMPT=0 \
        git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
            -c fetch.recurseSubmodules=false -c submodule.recurse=false \
            -c http.sslVerify=true "$@"
)

cleanup_failed_crs_provision() {
    safe_remove_runtime_path "$CRS_SOURCE_DIR" "$SOURCE_ROOT" "failed CRS provisioning" || true
}

require_expected_crs_origin() {
    remote_url=$(crs_git -C "$CRS_SOURCE_DIR" config --get remote.origin.url 2>/dev/null || true)
    if [ "$remote_url" != "$CRS_APPROVED_REPO_URL" ]; then
        ci_blocked "fetch_crs CRS checkout has unexpected origin: $remote_url"
        ci_blocked "fetch_crs expected origin: $CRS_APPROVED_REPO_URL"
        exit 77
    fi
}

verify_resolved_crs_commit() {
    resolved_commit=$(crs_git -C "$CRS_SOURCE_DIR" rev-parse --verify "$CRS_APPROVED_COMMIT^{commit}" 2>/dev/null || true)
    if [ "$resolved_commit" != "$CRS_APPROVED_COMMIT" ]; then
        ci_blocked "fetch_crs resolved CRS commit does not match the approved commit"
        exit 77
    fi
}

verify_fetched_crs_commit() {
    fetched_commit=$(crs_git -C "$CRS_SOURCE_DIR" rev-parse --verify "FETCH_HEAD^{commit}" 2>/dev/null || true)
    if [ "$fetched_commit" != "$CRS_APPROVED_COMMIT" ]; then
        ci_blocked "fetch_crs fetched CRS commit does not match the approved commit"
        exit 77
    fi
}

verify_checked_out_crs_commit() {
    checked_out_commit=$(crs_git -C "$CRS_SOURCE_DIR" rev-parse --verify "HEAD^{commit}" 2>/dev/null || true)
    if [ "$checked_out_commit" != "$CRS_APPROVED_COMMIT" ]; then
        ci_blocked "fetch_crs checked-out CRS commit does not match the approved commit"
        exit 77
    fi
}

provision_fresh_crs() {
    if [ -e "$CRS_SOURCE_DIR" ] || [ -L "$CRS_SOURCE_DIR" ]; then
        ci_blocked "fetch_crs refuses a pre-existing CRS source directory: $CRS_SOURCE_DIR"
        exit 77
    fi

    mkdir "$CRS_SOURCE_DIR" || {
        ci_blocked "fetch_crs could not create CRS source directory: $CRS_SOURCE_DIR"
        exit 77
    }
    if ! crs_git init "$CRS_SOURCE_DIR" >/dev/null 2>&1; then
        cleanup_failed_crs_provision
        ci_blocked "fetch_crs could not initialize the CRS source repository"
        exit 77
    fi
    if ! crs_git -C "$CRS_SOURCE_DIR" remote add origin "$CRS_APPROVED_REPO_URL"; then
        cleanup_failed_crs_provision
        ci_blocked "fetch_crs could not set the approved CRS origin"
        exit 77
    fi
    require_expected_crs_origin

    ci_info "fetch_crs fetching approved commit $CRS_APPROVED_COMMIT into $CRS_SOURCE_DIR"
    if ! crs_git -C "$CRS_SOURCE_DIR" fetch --depth 1 --no-tags origin "$CRS_APPROVED_COMMIT"; then
        cleanup_failed_crs_provision
        notice "CRS fetch blocked for approved commit $CRS_APPROVED_COMMIT"
        exit 77
    fi
    verify_fetched_crs_commit
    verify_resolved_crs_commit
    if ! crs_git -C "$CRS_SOURCE_DIR" checkout --detach "$CRS_APPROVED_COMMIT" >/dev/null 2>&1; then
        cleanup_failed_crs_provision
        ci_blocked "fetch_crs could not checkout the approved CRS commit"
        exit 77
    fi
    verify_checked_out_crs_commit

    if [ -e "$CRS_SOURCE_DIR/.gitmodules" ] || [ -L "$CRS_SOURCE_DIR/.gitmodules" ]; then
        ci_blocked "fetch_crs approved CRS commit declares submodules without an approved provenance rule"
        exit 77
    fi
}

require_approved_crs_provenance
ci_require_absolute_path "$SOURCE_ROOT" "SOURCE_ROOT" || exit 77
assert_safe_runtime_path "$SOURCE_ROOT" SOURCE_ROOT || exit 77
require_fetch_path "$CRS_SOURCE_DIR" "CRS_SOURCE_DIR"
mkdir -p "$SOURCE_ROOT" || {
    ci_blocked "fetch_crs could not create SOURCE_ROOT: $SOURCE_ROOT"
    exit 77
}
provision_fresh_crs
ci_info "fetch_crs ready CRS_SOURCE_DIR=$CRS_SOURCE_DIR commit=$CRS_APPROVED_COMMIT"
