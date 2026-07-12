#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
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

require_absolute_path "$SOURCE_ROOT" "SOURCE_ROOT"
assert_safe_runtime_path "$SOURCE_ROOT" SOURCE_ROOT || exit 77
require_fetch_path "$MODSECURITY_V3_SOURCE_DIR" "MODSECURITY_V3_SOURCE_DIR"
mkdir -p "$SOURCE_ROOT"

case "$FETCH_SCOPE" in
    v3)
        clone_source "$MODSECURITY_V3_GIT_URL" "$MODSECURITY_V3_GIT_REF" "$MODSECURITY_V3_SOURCE_DIR"
        ;;
    apache)
        clone_source "$MODSECURITY_V3_GIT_URL" "$MODSECURITY_V3_GIT_REF" "$MODSECURITY_V3_SOURCE_DIR"
        clone_external_connector_source MODSECURITY_APACHE "$MODSECURITY_APACHE_GIT_URL" "$MODSECURITY_APACHE_GIT_REF" "$MODSECURITY_APACHE_SOURCE_DIR" "$CI_MODSECURITY_APACHE_SOURCE_DIR_WAS_SET"
        ;;
    nginx)
        clone_source "$MODSECURITY_V3_GIT_URL" "$MODSECURITY_V3_GIT_REF" "$MODSECURITY_V3_SOURCE_DIR"
        clone_external_connector_source MODSECURITY_NGINX "$MODSECURITY_NGINX_GIT_URL" "$MODSECURITY_NGINX_GIT_REF" "$MODSECURITY_NGINX_SOURCE_DIR" "$CI_MODSECURITY_NGINX_SOURCE_DIR_WAS_SET"
        ;;
    all)
        clone_source "$MODSECURITY_V3_GIT_URL" "$MODSECURITY_V3_GIT_REF" "$MODSECURITY_V3_SOURCE_DIR"
        clone_external_connector_source MODSECURITY_APACHE "$MODSECURITY_APACHE_GIT_URL" "$MODSECURITY_APACHE_GIT_REF" "$MODSECURITY_APACHE_SOURCE_DIR" "$CI_MODSECURITY_APACHE_SOURCE_DIR_WAS_SET"
        clone_external_connector_source MODSECURITY_NGINX "$MODSECURITY_NGINX_GIT_URL" "$MODSECURITY_NGINX_GIT_REF" "$MODSECURITY_NGINX_SOURCE_DIR" "$CI_MODSECURITY_NGINX_SOURCE_DIR_WAS_SET"
        ;;
    *)
        ci_blocked "fetch_smoke_sources unknown fetch scope: $FETCH_SCOPE"
        exit 77
        ;;
esac
