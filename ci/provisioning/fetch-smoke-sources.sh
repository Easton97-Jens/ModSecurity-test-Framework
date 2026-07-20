#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$FRAMEWORK_ROOT}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

FETCH_SCOPE="${1:-all}"

ci_info "fetch_smoke_sources explicit fetch requested (no automatic background download)"

notice() {
    message=$1
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::notice::$message"
    else
        ci_info "fetch_smoke_sources $message"
    fi
}

require_absolute_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *)
            ci_blocked "fetch_smoke_sources $label must be absolute: $path"
            exit 77
            ;;
    esac
}

require_fetch_path() {
    path=$1
    label=$2
    require_absolute_path "$path" "$label"
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$SOURCE_ROOT"|"$SOURCE_ROOT"/*) ;;
        *)
            ci_blocked "fetch_smoke_sources $label must be under SOURCE_ROOT: $path"
            exit 77
            ;;
    esac
}

clone_source() {
    url=$1
    ref=$2
    dest=$3
    ci_require_https_github_repo_url "$url" "fetch_smoke_sources source url" || exit 77
    require_fetch_path "$dest" "clone destination"
    if [ -d "$dest/.git" ]; then
        ci_info "fetch_smoke_sources reusing $dest"
        git -C "$dest" fetch --tags --prune origin "$ref" || {
            notice "source fetch blocked for $url ref=$ref"
            exit 77
        }
        git -C "$dest" checkout --detach FETCH_HEAD >/dev/null 2>&1 || {
            ci_blocked "fetch_smoke_sources could not checkout ref=$ref in $dest"
            exit 77
        }
        git -C "$dest" submodule sync --recursive >/dev/null 2>&1 || true
        git -C "$dest" submodule update --init --recursive || {
            ci_blocked "fetch_smoke_sources submodule update failed: $dest"
            exit 77
        }
        return 0
    fi
    ci_info "fetch_smoke_sources fetching $url ref=$ref into $dest"
    set +e
    git clone --recursive --branch "$ref" "$url" "$dest"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        notice "source fetch blocked for $url ref=$ref"
        safe_remove_runtime_path "$dest" "$SOURCE_ROOT" "failed source clone" || true
        exit 77
    fi
}

clone_external_connector_source() {
    label=$1
    url=$2
    ref=$3
    dest=$4
    was_set=$5
    if [ "$ALLOW_EXTERNAL_CONNECTOR_REPOS" != "1" ]; then
        ci_info "fetch_smoke_sources $label connector source is repo-local; no external connector repo fetched"
        return 0
    fi
    if [ -z "$url" ]; then
        ci_blocked "fetch_smoke_sources $label external connector fetch requires ${label}_REPO_URL/${label}_GIT_URL"
        exit 77
    fi
    if [ "$was_set" != "1" ]; then
        ci_blocked "fetch_smoke_sources $label external connector fetch requires an explicit ${label}_SOURCE_DIR under SOURCE_ROOT"
        exit 77
    fi
    clone_source "$url" "$ref" "$dest"
}

cleanup_failed_modsecurity_v3_provision() {
    safe_remove_runtime_path "$MODSECURITY_V3_SOURCE_DIR" "$SOURCE_ROOT" "failed ModSecurity v3 provisioning" || true
}

require_expected_modsecurity_v3_origin() {
    v3_remote_url=$(ci_modsecurity_v3_git -C "$MODSECURITY_V3_SOURCE_DIR" config --get remote.origin.url 2>/dev/null || true)
    if [ "$v3_remote_url" != "$MODSECURITY_V3_APPROVED_REPO_URL" ]; then
        ci_blocked "fetch_smoke_sources ModSecurity v3 checkout has unexpected origin: $v3_remote_url"
        ci_blocked "fetch_smoke_sources ModSecurity v3 expected origin: $MODSECURITY_V3_APPROVED_REPO_URL"
        return 77
    fi
    return 0
}

verify_fetched_modsecurity_v3_commit() {
    v3_fetched_commit=$(ci_modsecurity_v3_git -C "$MODSECURITY_V3_SOURCE_DIR" rev-parse --verify "FETCH_HEAD^{commit}" 2>/dev/null || true)
    if [ "$v3_fetched_commit" != "$MODSECURITY_V3_APPROVED_COMMIT" ]; then
        ci_blocked "fetch_smoke_sources fetched ModSecurity v3 commit does not match the approved commit"
        return 77
    fi
    return 0
}

verify_resolved_modsecurity_v3_commit() {
    v3_resolved_commit=$(ci_modsecurity_v3_git -C "$MODSECURITY_V3_SOURCE_DIR" rev-parse --verify "$MODSECURITY_V3_APPROVED_COMMIT^{commit}" 2>/dev/null || true)
    if [ "$v3_resolved_commit" != "$MODSECURITY_V3_APPROVED_COMMIT" ]; then
        ci_blocked "fetch_smoke_sources resolved ModSecurity v3 commit does not match the approved commit"
        return 77
    fi
    return 0
}

provision_fresh_modsecurity_v3() {
    if [ -e "$MODSECURITY_V3_SOURCE_DIR" ] || [ -L "$MODSECURITY_V3_SOURCE_DIR" ]; then
        ci_blocked "fetch_smoke_sources refuses a pre-existing ModSecurity v3 source directory: $MODSECURITY_V3_SOURCE_DIR"
        exit 77
    fi

    mkdir "$MODSECURITY_V3_SOURCE_DIR" || {
        ci_blocked "fetch_smoke_sources could not create ModSecurity v3 source directory: $MODSECURITY_V3_SOURCE_DIR"
        exit 77
    }
    if ! ci_modsecurity_v3_git init "$MODSECURITY_V3_SOURCE_DIR" >/dev/null 2>&1; then
        cleanup_failed_modsecurity_v3_provision
        ci_blocked "fetch_smoke_sources could not initialize the ModSecurity v3 source repository"
        exit 77
    fi
    if ! ci_modsecurity_v3_git -C "$MODSECURITY_V3_SOURCE_DIR" remote add origin "$MODSECURITY_V3_APPROVED_REPO_URL"; then
        cleanup_failed_modsecurity_v3_provision
        ci_blocked "fetch_smoke_sources could not set the approved ModSecurity v3 origin"
        exit 77
    fi
    if ! require_expected_modsecurity_v3_origin; then
        cleanup_failed_modsecurity_v3_provision
        exit 77
    fi

    ci_info "fetch_smoke_sources fetching approved ModSecurity v3 commit $MODSECURITY_V3_APPROVED_COMMIT into $MODSECURITY_V3_SOURCE_DIR"
    if ! ci_modsecurity_v3_git -C "$MODSECURITY_V3_SOURCE_DIR" fetch --depth 1 --no-tags origin "$MODSECURITY_V3_APPROVED_COMMIT"; then
        cleanup_failed_modsecurity_v3_provision
        notice "ModSecurity v3 fetch blocked for approved commit $MODSECURITY_V3_APPROVED_COMMIT"
        exit 77
    fi
    if ! verify_fetched_modsecurity_v3_commit || ! verify_resolved_modsecurity_v3_commit; then
        cleanup_failed_modsecurity_v3_provision
        exit 77
    fi
    if ! ci_modsecurity_v3_git -C "$MODSECURITY_V3_SOURCE_DIR" checkout --detach "$MODSECURITY_V3_APPROVED_COMMIT" >/dev/null 2>&1; then
        cleanup_failed_modsecurity_v3_provision
        ci_blocked "fetch_smoke_sources could not checkout the approved ModSecurity v3 commit"
        exit 77
    fi
    if ! ci_require_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR"; then
        cleanup_failed_modsecurity_v3_provision
        exit 77
    fi
}

require_absolute_path "$SOURCE_ROOT" "SOURCE_ROOT"
assert_safe_runtime_path "$SOURCE_ROOT" SOURCE_ROOT || exit 77
require_fetch_path "$MODSECURITY_V3_SOURCE_DIR" "MODSECURITY_V3_SOURCE_DIR"
ci_require_approved_modsecurity_v3_provenance || exit 77
mkdir -p "$SOURCE_ROOT"

case "$FETCH_SCOPE" in
    v3)
        provision_fresh_modsecurity_v3
        ;;
    apache)
        provision_fresh_modsecurity_v3
        clone_external_connector_source MODSECURITY_APACHE "$MODSECURITY_APACHE_GIT_URL" "$MODSECURITY_APACHE_GIT_REF" "$MODSECURITY_APACHE_SOURCE_DIR" "$CI_MODSECURITY_APACHE_SOURCE_DIR_WAS_SET"
        ;;
    nginx)
        provision_fresh_modsecurity_v3
        clone_external_connector_source MODSECURITY_NGINX "$MODSECURITY_NGINX_GIT_URL" "$MODSECURITY_NGINX_GIT_REF" "$MODSECURITY_NGINX_SOURCE_DIR" "$CI_MODSECURITY_NGINX_SOURCE_DIR_WAS_SET"
        ;;
    all)
        provision_fresh_modsecurity_v3
        clone_external_connector_source MODSECURITY_APACHE "$MODSECURITY_APACHE_GIT_URL" "$MODSECURITY_APACHE_GIT_REF" "$MODSECURITY_APACHE_SOURCE_DIR" "$CI_MODSECURITY_APACHE_SOURCE_DIR_WAS_SET"
        clone_external_connector_source MODSECURITY_NGINX "$MODSECURITY_NGINX_GIT_URL" "$MODSECURITY_NGINX_GIT_REF" "$MODSECURITY_NGINX_SOURCE_DIR" "$CI_MODSECURITY_NGINX_SOURCE_DIR_WAS_SET"
        ;;
    *)
        ci_blocked "fetch_smoke_sources unknown fetch scope: $FETCH_SCOPE"
        exit 77
        ;;
esac
