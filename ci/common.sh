#!/bin/sh

# Shared CI/runtime helper configuration.
#
# This file is intentionally passive: sourcing it defines variables and
# functions only. It must not fetch sources, create directories, install
# dependencies, run validation, or otherwise mutate the filesystem.

DEFAULT_BRANCH="${DEFAULT_BRANCH:-master}"
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-${REPO_ROOT:-}}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-${REPO_ROOT:-$FRAMEWORK_ROOT}}"
DEFAULT_STATE_HOME="${DEFAULT_STATE_HOME:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}}"
DEFAULT_BUILD_ROOT="${DEFAULT_BUILD_ROOT:-/src/ModSecurity-conector-build}"
BUILD_ROOT="${BUILD_ROOT:-$DEFAULT_BUILD_ROOT}"
TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp}"
LOG_ROOT="${LOG_ROOT:-$BUILD_ROOT/logs}"
if [ -n "${SOURCE_ROOT:-}" ]; then
    CI_SOURCE_ROOT_WAS_SET=1
else
    CI_SOURCE_ROOT_WAS_SET=0
fi
if [ -n "${MODSECURITY_APACHE_SOURCE_DIR:-}" ]; then
    CI_MODSECURITY_APACHE_SOURCE_DIR_WAS_SET=1
else
    CI_MODSECURITY_APACHE_SOURCE_DIR_WAS_SET=0
fi
if [ -n "${MODSECURITY_NGINX_SOURCE_DIR:-}" ]; then
    CI_MODSECURITY_NGINX_SOURCE_DIR_WAS_SET=1
else
    CI_MODSECURITY_NGINX_SOURCE_DIR_WAS_SET=0
fi
DEFAULT_SOURCE_ROOT="${DEFAULT_SOURCE_ROOT:-/src}"
SOURCE_ROOT="${SOURCE_ROOT:-$DEFAULT_SOURCE_ROOT}"
DEFAULT_PYTHON="${DEFAULT_PYTHON:-python3}"
DEFAULT_MODSECURITY_V3_SOURCE_DIR="${DEFAULT_MODSECURITY_V3_SOURCE_DIR:-$SOURCE_ROOT/ModSecurity_V3}"
MODSECURITY_SOURCE_DIR="${MODSECURITY_SOURCE_DIR:-${MODSECURITY_V3_SOURCE_DIR:-${MODSECURITY_V3_ROOT:-$DEFAULT_MODSECURITY_V3_SOURCE_DIR}}}"
MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-$MODSECURITY_SOURCE_DIR}"
MODSECURITY_V3_ROOT="${MODSECURITY_V3_ROOT:-$MODSECURITY_SOURCE_DIR}"

# ModSecurity test variant defaults
: "${MODSECURITY_TEST_VARIANT:=no-crs}"
: "${MODSECURITY_MRTS_VARIANT:=no-mrts}"

# OWASP Core Rule Set defaults
: "${CRS_REPO_URL:=https://github.com/coreruleset/coreruleset.git}"
: "${CRS_GIT_REF:=v4.26.0}"

# CRS paths
: "${CRS_SOURCE_DIR:=${SOURCE_ROOT}/coreruleset}"
: "${CRS_RUNTIME_DIR:=${BUILD_ROOT}/crs}"

# Optional preamble injected before generated local case rules
: "${MODSECURITY_RULE_PREAMBLE_FILE:=}"

if [ -n "${CONNECTOR_ROOT:-}" ]; then
    DEFAULT_MODSECURITY_APACHE_SOURCE_DIR="${DEFAULT_MODSECURITY_APACHE_SOURCE_DIR:-$CONNECTOR_ROOT/connectors/apache}"
    DEFAULT_MODSECURITY_NGINX_SOURCE_DIR="${DEFAULT_MODSECURITY_NGINX_SOURCE_DIR:-$CONNECTOR_ROOT/connectors/nginx}"
else
    DEFAULT_MODSECURITY_APACHE_SOURCE_DIR="${DEFAULT_MODSECURITY_APACHE_SOURCE_DIR:-}"
    DEFAULT_MODSECURITY_NGINX_SOURCE_DIR="${DEFAULT_MODSECURITY_NGINX_SOURCE_DIR:-}"
fi
MODSECURITY_APACHE_SOURCE_DIR="${MODSECURITY_APACHE_SOURCE_DIR:-$DEFAULT_MODSECURITY_APACHE_SOURCE_DIR}"
MODSECURITY_NGINX_SOURCE_DIR="${MODSECURITY_NGINX_SOURCE_DIR:-$DEFAULT_MODSECURITY_NGINX_SOURCE_DIR}"

MODSECURITY_REPO_URL="${MODSECURITY_REPO_URL:-${MODSECURITY_V3_GIT_URL:-https://github.com/owasp-modsecurity/ModSecurity.git}}"
MODSECURITY_GIT_REF="${MODSECURITY_GIT_REF:-${MODSECURITY_V3_GIT_REF:-v3/master}}"
MODSECURITY_V3_GIT_URL="${MODSECURITY_V3_GIT_URL:-$MODSECURITY_REPO_URL}"
MODSECURITY_V3_GIT_REF="${MODSECURITY_V3_GIT_REF:-$MODSECURITY_GIT_REF}"

ALLOW_EXTERNAL_CONNECTOR_REPOS="${ALLOW_EXTERNAL_CONNECTOR_REPOS:-0}"
MODSECURITY_APACHE_REPO_URL="${MODSECURITY_APACHE_REPO_URL:-${MODSECURITY_APACHE_GIT_URL:-}}"
MODSECURITY_APACHE_GIT_URL="${MODSECURITY_APACHE_GIT_URL:-$MODSECURITY_APACHE_REPO_URL}"
MODSECURITY_APACHE_GIT_REF="${MODSECURITY_APACHE_GIT_REF:-$DEFAULT_BRANCH}"

MODSECURITY_NGINX_REPO_URL="${MODSECURITY_NGINX_REPO_URL:-${MODSECURITY_NGINX_GIT_URL:-}}"
MODSECURITY_NGINX_GIT_URL="${MODSECURITY_NGINX_GIT_URL:-$MODSECURITY_NGINX_REPO_URL}"
MODSECURITY_NGINX_GIT_REF="${MODSECURITY_NGINX_GIT_REF:-$DEFAULT_BRANCH}"

HTTPD_VERSION="${HTTPD_VERSION:-2.4.67}"
HTTPD_SOURCE_URL="${HTTPD_SOURCE_URL:-https://downloads.apache.org/httpd/httpd-$HTTPD_VERSION.tar.bz2}"
HTTPD_SHA256="${HTTPD_SHA256:-}"
HTTPD_SHA256_URL="${HTTPD_SHA256_URL:-$HTTPD_SOURCE_URL.sha256}"
APR_VERSION="${APR_VERSION:-1.7.6}"
APR_SOURCE_URL="${APR_SOURCE_URL:-https://downloads.apache.org/apr/apr-$APR_VERSION.tar.bz2}"
APR_SHA256="${APR_SHA256:-}"
APR_SHA256_URL="${APR_SHA256_URL:-$APR_SOURCE_URL.sha256}"
APR_UTIL_VERSION="${APR_UTIL_VERSION:-1.6.3}"
APR_UTIL_SOURCE_URL="${APR_UTIL_SOURCE_URL:-https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2}"
APR_UTIL_SHA256="${APR_UTIL_SHA256:-}"
APR_UTIL_SHA256_URL="${APR_UTIL_SHA256_URL:-$APR_UTIL_SOURCE_URL.sha256}"
PCRE2_VERSION="${PCRE2_VERSION:-10.47}"
PCRE2_SOURCE_URL="${PCRE2_SOURCE_URL:-https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_VERSION/pcre2-$PCRE2_VERSION.tar.bz2}"
PCRE2_SHA256="${PCRE2_SHA256:-}"
PCRE2_SHA256_URL="${PCRE2_SHA256_URL:-}"

NGINX_SOURCE_MODE="${NGINX_SOURCE_MODE:-github-release}"
NGINX_SOURCE_REPO_URL="${NGINX_SOURCE_REPO_URL:-${NGINX_GITHUB_REPO:-https://github.com/nginx/nginx}}"
NGINX_GITHUB_REPO="${NGINX_GITHUB_REPO:-$NGINX_SOURCE_REPO_URL}"
NGINX_RELEASE_TAG="${NGINX_RELEASE_TAG:-${NGINX_SOURCE_GIT_REF:-latest}}"
NGINX_SOURCE_GIT_REF="${NGINX_SOURCE_GIT_REF:-$NGINX_RELEASE_TAG}"
NGINX_SHA256="${NGINX_SHA256:-}"

HAPROXY_VERSION="${HAPROXY_VERSION:-3.2.19}"
HAPROXY_SOURCE_URL="${HAPROXY_SOURCE_URL:-https://www.haproxy.org/download/3.2/src/haproxy-$HAPROXY_VERSION.tar.gz}"
HAPROXY_SHA256_URL="${HAPROXY_SHA256_URL:-$HAPROXY_SOURCE_URL.sha256}"
HAPROXY_SHA256="${HAPROXY_SHA256:-b08ebbd57f575012e4a5eb5b772721531fbacf6913ffd334f0281736a1ad78b6}"
HAPROXY_SOURCE_ROOT="${HAPROXY_SOURCE_ROOT:-$SOURCE_ROOT/haproxy}"
HAPROXY_DOWNLOAD_DIR="${HAPROXY_DOWNLOAD_DIR:-$HAPROXY_SOURCE_ROOT/downloads}"
HAPROXY_SOURCE_DIR="${HAPROXY_SOURCE_DIR:-$HAPROXY_SOURCE_ROOT/haproxy-$HAPROXY_VERSION}"
HAPROXY_RUNTIME_BUILD_DIR="${HAPROXY_RUNTIME_BUILD_DIR:-$BUILD_ROOT/haproxy-runtime-build}"
HAPROXY_RUNTIME_BUILD_WORKTREE="${HAPROXY_RUNTIME_BUILD_WORKTREE:-$HAPROXY_RUNTIME_BUILD_DIR/worktree}"
HAPROXY_RUNTIME_DIR="${HAPROXY_RUNTIME_DIR:-$BUILD_ROOT/haproxy-runtime/haproxy}"
HAPROXY_BIN="${HAPROXY_BIN:-$HAPROXY_RUNTIME_DIR/sbin/haproxy}"

APACHE_BIN="${APACHE_BIN:-}"
APACHECTL_BIN="${APACHECTL_BIN:-}"
APXS_BIN="${APXS_BIN:-${APXS:-}}"
NGINX_BIN="${NGINX_BIN:-}"
MODSECURITY_PKG_CONFIG="${MODSECURITY_PKG_CONFIG:-}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-}"
MODSECURITY_INCLUDE_DIR="${MODSECURITY_INCLUDE_DIR:-}"

CI_APACHE_BIN_CANDIDATES="${CI_APACHE_BIN_CANDIDATES:-apache2 httpd apachectl}"
CI_APXS_BIN_CANDIDATES="${CI_APXS_BIN_CANDIDATES:-apxs apxs2}"
CI_NGINX_BIN_CANDIDATES="${CI_NGINX_BIN_CANDIDATES:-nginx}"
CI_INSTALLED_LIB_SEARCH_DIRS="${CI_INSTALLED_LIB_SEARCH_DIRS:-/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /usr/local/lib /usr/lib64 /usr/lib}"
CI_INSTALLED_INCLUDE_SEARCH_DIRS="${CI_INSTALLED_INCLUDE_SEARCH_DIRS:-/usr/include /usr/local/include /opt/include}"

ci_info() {
    echo "INFO: $*"
    return 0
}

ci_warn() {
    echo "WARN: $*"
    return 0
}

ci_blocked() {
    echo "BLOCKED: $*"
    return 0
}

ci_error() {
    echo "ERROR: $*" >&2
    return 0
}

ci_python() {
    if [ -n "${PYTHON:-}" ]; then
        printf '%s\n' "$PYTHON"
        return 0
    fi
    if [ -n "${CONNECTOR_ROOT:-}" ] && [ -x "$CONNECTOR_ROOT/.venv/bin/python" ]; then
        printf '%s\n' "$CONNECTOR_ROOT/.venv/bin/python"
        return 0
    fi
    if [ -n "${FRAMEWORK_ROOT:-}" ] && [ -x "$FRAMEWORK_ROOT/.venv/bin/python" ]; then
        printf '%s\n' "$FRAMEWORK_ROOT/.venv/bin/python"
        return 0
    fi
    printf '%s\n' "$DEFAULT_PYTHON"
    return 0
}

ci_default_jobs() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    else
        getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
    fi
    return 0
}

ci_find_bin_multi() {
    for name in "$@"; do
        path=$(command -v "$name" 2>/dev/null || true)
        if [ -n "$path" ]; then
            printf '%s\n' "$path"
            return 0
        fi
    done
    return 1
}

ci_resolve_apache_from_apxs() {
    apxs_path=$1
    [ -n "$apxs_path" ] || return 1
    sbin_dir=$("$apxs_path" -q SBINDIR 2>/dev/null || true)
    target_name=$("$apxs_path" -q TARGET 2>/dev/null || true)
    if [ -n "$sbin_dir" ] && [ -n "$target_name" ] && [ -x "$sbin_dir/$target_name" ]; then
        printf '%s\n' "$sbin_dir/$target_name"
        return 0
    fi
    if [ -n "$sbin_dir" ] && [ -x "$sbin_dir/apache2" ]; then
        printf '%s\n' "$sbin_dir/apache2"
        return 0
    fi
    if [ -n "$sbin_dir" ] && [ -x "$sbin_dir/httpd" ]; then
        printf '%s\n' "$sbin_dir/httpd"
        return 0
    fi
    return 1
}

ci_canonical_existing() {
    target_path=$1
    if [ -e "$target_path" ]; then
        (cd "$target_path" 2>/dev/null && pwd -P)
        return $?
    else
        return 1
    fi
}

ci_require_absolute_path() {
    path=$1
    label=$2
    case "$path" in
        /*) return 0 ;;
        *) ci_blocked "$label must be absolute: $path"; return 77 ;;
    esac
    return 0
}

ci_git_value() {
    git_dir=$1
    shift
    if git -C "$git_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$git_dir" "$@" 2>/dev/null || true
    fi
    return 0
}
