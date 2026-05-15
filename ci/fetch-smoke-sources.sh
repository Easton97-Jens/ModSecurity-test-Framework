#!/bin/sh
set -eu

BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-test-Framework-build}"
SOURCE_ROOT="${SOURCE_ROOT:-${RUNNER_TEMP:-$BUILD_ROOT}/sources}"
MODSECURITY_V3_GIT_URL="${MODSECURITY_V3_GIT_URL:-https://github.com/owasp-modsecurity/ModSecurity.git}"
MODSECURITY_V3_GIT_REF="${MODSECURITY_V3_GIT_REF:-v3/master}"
MODSECURITY_APACHE_GIT_URL="${MODSECURITY_APACHE_GIT_URL:-https://github.com/owasp-modsecurity/ModSecurity-apache.git}"
MODSECURITY_APACHE_GIT_REF="${MODSECURITY_APACHE_GIT_REF:-master}"
MODSECURITY_NGINX_GIT_URL="${MODSECURITY_NGINX_GIT_URL:-https://github.com/owasp-modsecurity/ModSecurity-nginx.git}"
MODSECURITY_NGINX_GIT_REF="${MODSECURITY_NGINX_GIT_REF:-master}"
MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-$SOURCE_ROOT/ModSecurity_V3}"
MODSECURITY_APACHE_SOURCE_DIR="${MODSECURITY_APACHE_SOURCE_DIR:-$SOURCE_ROOT/ModSecurity-apache}"
MODSECURITY_NGINX_SOURCE_DIR="${MODSECURITY_NGINX_SOURCE_DIR:-$SOURCE_ROOT/ModSecurity-nginx}"
FETCH_SCOPE="${1:-all}"

notice() {
    message=$1
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::notice::$message"
    else
        echo "fetch_smoke_sources: $message"
    fi
}

require_absolute_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *)
            echo "fetch_smoke_sources: blocked $label must be absolute: $path"
            exit 77
            ;;
    esac
}

require_fetch_path() {
    path=$1
    label=$2
    require_absolute_path "$path" "$label"
    case "$path" in
        /root/conecter|/root/conecter/*)
            echo "fetch_smoke_sources: blocked $label must not be inside /root/conecter: $path"
            exit 77
            ;;
        *) ;;
    esac
    case "$path" in
        "$SOURCE_ROOT"|"$SOURCE_ROOT"/*) ;;
        *)
            echo "fetch_smoke_sources: blocked $label must be under SOURCE_ROOT: $path"
            exit 77
            ;;
    esac
}

clone_source() {
    url=$1
    ref=$2
    dest=$3
    require_fetch_path "$dest" "clone destination"
    if [ -d "$dest/.git" ]; then
        echo "fetch_smoke_sources: reusing $dest"
        return 0
    fi
    echo "fetch_smoke_sources: fetching $url ref=$ref into $dest"
    set +e
    git clone --depth 1 --branch "$ref" "$url" "$dest"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        notice "source fetch blocked for $url ref=$ref"
        rm -rf "$dest"
    fi
}

require_absolute_path "$SOURCE_ROOT" "SOURCE_ROOT"
case "$SOURCE_ROOT" in
    /root/conecter|/root/conecter/*)
        echo "fetch_smoke_sources: blocked SOURCE_ROOT must not be inside /root/conecter: $SOURCE_ROOT"
        exit 77
        ;;
    *) ;;
esac
require_fetch_path "$MODSECURITY_V3_SOURCE_DIR" "MODSECURITY_V3_SOURCE_DIR"
require_fetch_path "$MODSECURITY_APACHE_SOURCE_DIR" "MODSECURITY_APACHE_SOURCE_DIR"
require_fetch_path "$MODSECURITY_NGINX_SOURCE_DIR" "MODSECURITY_NGINX_SOURCE_DIR"
mkdir -p "$SOURCE_ROOT"

case "$FETCH_SCOPE" in
    apache)
        clone_source "$MODSECURITY_V3_GIT_URL" "$MODSECURITY_V3_GIT_REF" "$MODSECURITY_V3_SOURCE_DIR"
        clone_source "$MODSECURITY_APACHE_GIT_URL" "$MODSECURITY_APACHE_GIT_REF" "$MODSECURITY_APACHE_SOURCE_DIR"
        ;;
    nginx)
        clone_source "$MODSECURITY_V3_GIT_URL" "$MODSECURITY_V3_GIT_REF" "$MODSECURITY_V3_SOURCE_DIR"
        clone_source "$MODSECURITY_NGINX_GIT_URL" "$MODSECURITY_NGINX_GIT_REF" "$MODSECURITY_NGINX_SOURCE_DIR"
        ;;
    all)
        clone_source "$MODSECURITY_V3_GIT_URL" "$MODSECURITY_V3_GIT_REF" "$MODSECURITY_V3_SOURCE_DIR"
        clone_source "$MODSECURITY_APACHE_GIT_URL" "$MODSECURITY_APACHE_GIT_REF" "$MODSECURITY_APACHE_SOURCE_DIR"
        clone_source "$MODSECURITY_NGINX_GIT_URL" "$MODSECURITY_NGINX_GIT_REF" "$MODSECURITY_NGINX_SOURCE_DIR"
        ;;
    *)
        echo "fetch_smoke_sources: blocked unknown fetch scope: $FETCH_SCOPE"
        exit 77
        ;;
esac
