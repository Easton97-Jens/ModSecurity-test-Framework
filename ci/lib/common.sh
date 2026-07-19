#!/bin/sh
# shellcheck shell=sh disable=SC2034,SC2317

# Shared CI/runtime helper configuration.
#
# This file is intentionally passive: sourcing it defines variables and
# functions only. It must not fetch sources, create directories, install
# dependencies, run validation, or otherwise mutate the filesystem.

DEFAULT_BRANCH="${DEFAULT_BRANCH:-master}"
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-${REPO_ROOT:-}}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-${REPO_ROOT:-$FRAMEWORK_ROOT}}"
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_STATE_ROOT="${VERIFIED_STATE_ROOT:-$VERIFIED_RUN_ROOT/state}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
VERIFIED_SOURCE_ROOT="${VERIFIED_SOURCE_ROOT:-$VERIFIED_RUN_ROOT/src}"
VERIFIED_TMP_ROOT="${VERIFIED_TMP_ROOT:-$VERIFIED_RUN_ROOT/tmp}"
VERIFIED_LOG_ROOT="${VERIFIED_LOG_ROOT:-$VERIFIED_RUN_ROOT/logs}"
# Keep immutable components apart from connector-local runtime artifacts.  The
# parent cache root is intentionally versioned so a legacy unmarked
# component-cache tree is never implicitly trusted or mutated.
CACHE_ROOT="${CACHE_ROOT:-$VERIFIED_RUN_ROOT/cache-v2}"
VERIFIED_COMPONENT_CACHE="${VERIFIED_COMPONENT_CACHE:-$CACHE_ROOT/shared}"
NGINX_HARNESS_PARENT="${NGINX_HARNESS_PARENT:-$VERIFIED_RUN_ROOT/nginx-harness}"
DEFAULT_STATE_HOME="${DEFAULT_STATE_HOME:-$VERIFIED_STATE_ROOT}"
DEFAULT_BUILD_ROOT="${DEFAULT_BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
BUILD_ROOT="${BUILD_ROOT:-$DEFAULT_BUILD_ROOT}"
TMP_ROOT="${TMP_ROOT:-$VERIFIED_TMP_ROOT}"
LOG_ROOT="${LOG_ROOT:-$VERIFIED_LOG_ROOT}"
CONNECTOR_COMPONENT_CACHE="${CONNECTOR_COMPONENT_CACHE:-$VERIFIED_COMPONENT_CACHE}"
if [ -n "${ENVOY_BIN:-}" ]; then
    ENVOY_BIN_WAS_SET=1
else
    ENVOY_BIN_WAS_SET=0
fi
if [ -n "${TRAEFIK_BIN:-}" ]; then
    TRAEFIK_BIN_WAS_SET=1
else
    TRAEFIK_BIN_WAS_SET=0
fi
if [ -n "${LIGHTTPD_BIN:-}" ]; then
    LIGHTTPD_BIN_WAS_SET=1
else
    LIGHTTPD_BIN_WAS_SET=0
fi
if [ -n "${HAPROXY_BIN:-}" ]; then
    HAPROXY_BIN_WAS_SET=1
else
    HAPROXY_BIN_WAS_SET=0
fi

# Open connector runtime component defaults. These are passive local paths only:
# checks, downloads, installs, and directory creation happen outside common.sh.
ENVOY_VERSION="${ENVOY_VERSION:-1.38.2}"
ENVOY_SOURCE_URL="${ENVOY_SOURCE_URL:-https://github.com/envoyproxy/envoy/releases}"
ENVOY_INSTALL_DOCS_URL="${ENVOY_INSTALL_DOCS_URL:-https://www.envoyproxy.io/docs/envoy/latest/start/install}"
ENVOY_DOWNLOAD_URL="${ENVOY_DOWNLOAD_URL:-https://github.com/envoyproxy/envoy/releases/download/v$ENVOY_VERSION/envoy-$ENVOY_VERSION-linux-x86_64}"
ENVOY_SHA256="${ENVOY_SHA256:-87744a1fc998d677078c9703113a192d0830badc6888662441632847fcb38899}"
ENVOY_SHA256_URL="${ENVOY_SHA256_URL:-https://github.com/envoyproxy/envoy/releases/download/v$ENVOY_VERSION/checksums.txt.asc}"
ENVOY_COMPONENT_ROOT="${ENVOY_COMPONENT_ROOT:-$CONNECTOR_COMPONENT_CACHE/envoy}"
ENVOY_RUNTIME_ROOT="${ENVOY_RUNTIME_ROOT:-$VERIFIED_RUN_ROOT/envoy-smoke}"
ENVOY_CONFIG_ROOT="${ENVOY_CONFIG_ROOT:-$ENVOY_RUNTIME_ROOT/config}"
ENVOY_LOG_ROOT="${ENVOY_LOG_ROOT:-$VERIFIED_LOG_ROOT/envoy-smoke}"
ENVOY_RESULT_ROOT="${ENVOY_RESULT_ROOT:-$VERIFIED_RUN_ROOT/envoy-smoke}"
ENVOY_BIN="${ENVOY_BIN:-$ENVOY_COMPONENT_ROOT/bin/envoy}"
ENVOY_SOURCE_ROOT="${ENVOY_SOURCE_ROOT:-$ENVOY_COMPONENT_ROOT/src/envoy-$ENVOY_VERSION}"
ENVOY_BUILD_ROOT="${ENVOY_BUILD_ROOT:-$BUILD_ROOT/envoy-connector}"
ENVOY_SMOKE_PORT="${ENVOY_SMOKE_PORT:-18080}"
ENVOY_UPSTREAM_PORT="${ENVOY_UPSTREAM_PORT:-18081}"
ENVOY_AUTHZ_PORT="${ENVOY_AUTHZ_PORT:-18082}"
ENVOY_INTEGRATION_MODE="${ENVOY_INTEGRATION_MODE:-ext_authz}"

TRAEFIK_VERSION="${TRAEFIK_VERSION:-3.7.5}"
TRAEFIK_SOURCE_URL="${TRAEFIK_SOURCE_URL:-https://github.com/traefik/traefik/releases}"
TRAEFIK_INSTALL_DOCS_URL="${TRAEFIK_INSTALL_DOCS_URL:-https://doc.traefik.io/traefik/getting-started/install-traefik/}"
TRAEFIK_DOWNLOAD_URL="${TRAEFIK_DOWNLOAD_URL:-https://github.com/traefik/traefik/releases/download/v$TRAEFIK_VERSION/traefik_v${TRAEFIK_VERSION}_linux_amd64.tar.gz}"
TRAEFIK_SHA256="${TRAEFIK_SHA256:-9da81a928fde965c2c4678698bbc28bc3f600223b14c32b35bd480bf5ec863dc}"
TRAEFIK_SHA256_URL="${TRAEFIK_SHA256_URL:-https://github.com/traefik/traefik/releases/download/v$TRAEFIK_VERSION/traefik_v${TRAEFIK_VERSION}_checksums.txt}"
TRAEFIK_COMPONENT_ROOT="${TRAEFIK_COMPONENT_ROOT:-$CONNECTOR_COMPONENT_CACHE/traefik}"
TRAEFIK_RUNTIME_ROOT="${TRAEFIK_RUNTIME_ROOT:-$VERIFIED_RUN_ROOT/traefik-smoke}"
TRAEFIK_CONFIG_ROOT="${TRAEFIK_CONFIG_ROOT:-$TRAEFIK_RUNTIME_ROOT/config}"
TRAEFIK_LOG_ROOT="${TRAEFIK_LOG_ROOT:-$VERIFIED_LOG_ROOT/traefik-smoke}"
TRAEFIK_RESULT_ROOT="${TRAEFIK_RESULT_ROOT:-$VERIFIED_RUN_ROOT/traefik-smoke}"
TRAEFIK_BIN="${TRAEFIK_BIN:-$TRAEFIK_COMPONENT_ROOT/bin/traefik}"
TRAEFIK_SOURCE_ROOT="${TRAEFIK_SOURCE_ROOT:-$TRAEFIK_COMPONENT_ROOT/src/traefik-$TRAEFIK_VERSION}"
TRAEFIK_BUILD_ROOT="${TRAEFIK_BUILD_ROOT:-$BUILD_ROOT/traefik-connector}"
TRAEFIK_SMOKE_PORT="${TRAEFIK_SMOKE_PORT:-18180}"
TRAEFIK_UPSTREAM_PORT="${TRAEFIK_UPSTREAM_PORT:-18181}"
TRAEFIK_AUTHZ_PORT="${TRAEFIK_AUTHZ_PORT:-18182}"
TRAEFIK_INTEGRATION_MODE="${TRAEFIK_INTEGRATION_MODE:-forwardAuth}"

LIGHTTPD_VERSION="${LIGHTTPD_VERSION:-1.4.84}"
LIGHTTPD_SOURCE_URL="${LIGHTTPD_SOURCE_URL:-https://download.lighttpd.net/lighttpd/releases-1.4.x/}"
LIGHTTPD_RELEASE_INDEX_URL="${LIGHTTPD_RELEASE_INDEX_URL:-$LIGHTTPD_SOURCE_URL}"
LIGHTTPD_LATEST_URL="${LIGHTTPD_LATEST_URL:-https://download.lighttpd.net/lighttpd/releases-1.4.x/latest.txt}"
LIGHTTPD_DOWNLOAD_URL="${LIGHTTPD_DOWNLOAD_URL:-https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-$LIGHTTPD_VERSION.tar.xz}"
LIGHTTPD_SHA256="${LIGHTTPD_SHA256:-076dd43bec8f2ba9ce6db7e7ca7e8ad72271cd529805ead2400b56efaa026f70}"
LIGHTTPD_SHA256_URL="${LIGHTTPD_SHA256_URL:-https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-$LIGHTTPD_VERSION.sha256sum}"
LIGHTTPD_COMPONENT_ROOT="${LIGHTTPD_COMPONENT_ROOT:-$CONNECTOR_COMPONENT_CACHE/lighttpd}"
LIGHTTPD_RUNTIME_ROOT="${LIGHTTPD_RUNTIME_ROOT:-$VERIFIED_RUN_ROOT/lighttpd-smoke}"
LIGHTTPD_CONFIG_ROOT="${LIGHTTPD_CONFIG_ROOT:-$LIGHTTPD_RUNTIME_ROOT/config}"
LIGHTTPD_LOG_ROOT="${LIGHTTPD_LOG_ROOT:-$VERIFIED_LOG_ROOT/lighttpd-smoke}"
LIGHTTPD_RESULT_ROOT="${LIGHTTPD_RESULT_ROOT:-$VERIFIED_RUN_ROOT/lighttpd-smoke}"
LIGHTTPD_BIN="${LIGHTTPD_BIN:-$LIGHTTPD_COMPONENT_ROOT/bin/lighttpd}"
LIGHTTPD_SOURCE_DIR="${LIGHTTPD_SOURCE_DIR:-$LIGHTTPD_COMPONENT_ROOT/src/lighttpd-$LIGHTTPD_VERSION}"
LIGHTTPD_BUILD_ROOT="${LIGHTTPD_BUILD_ROOT:-$LIGHTTPD_COMPONENT_ROOT/build/lighttpd-$LIGHTTPD_VERSION}"
LIGHTTPD_INCLUDE_DIR="${LIGHTTPD_INCLUDE_DIR:-$LIGHTTPD_SOURCE_DIR/src}"
LIGHTTPD_CONNECTOR_BUILD_ROOT="${LIGHTTPD_CONNECTOR_BUILD_ROOT:-$BUILD_ROOT/lighttpd-connector}"
LIGHTTPD_MODULE_DIR="${LIGHTTPD_MODULE_DIR:-$LIGHTTPD_CONNECTOR_BUILD_ROOT/modules}"
LIGHTTPD_SMOKE_PORT="${LIGHTTPD_SMOKE_PORT:-18280}"
LIGHTTPD_UPSTREAM_PORT="${LIGHTTPD_UPSTREAM_PORT:-18281}"
LIGHTTPD_AUTHZ_PORT="${LIGHTTPD_AUTHZ_PORT:-18282}"
LIGHTTPD_INTEGRATION_MODE="${LIGHTTPD_INTEGRATION_MODE:-sidecar_proxy}"
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
DEFAULT_SOURCE_ROOT="${DEFAULT_SOURCE_ROOT:-$VERIFIED_SOURCE_ROOT}"
SOURCE_ROOT="${SOURCE_ROOT:-$DEFAULT_SOURCE_ROOT}"
DEFAULT_PYTHON="${DEFAULT_PYTHON:-python3}"
DEFAULT_MODSECURITY_V3_SOURCE_DIR="${DEFAULT_MODSECURITY_V3_SOURCE_DIR:-$SOURCE_ROOT/ModSecurity_V3}"
MODSECURITY_SOURCE_DIR="${MODSECURITY_SOURCE_DIR:-${MODSECURITY_V3_SOURCE_DIR:-${MODSECURITY_V3_ROOT:-$DEFAULT_MODSECURITY_V3_SOURCE_DIR}}}"
MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-$MODSECURITY_SOURCE_DIR}"
MODSECURITY_V3_ROOT="${MODSECURITY_V3_ROOT:-$MODSECURITY_SOURCE_DIR}"

# ModSecurity test variant defaults
: "${MODSECURITY_TEST_VARIANT:=no-crs}"
: "${MODSECURITY_MRTS_VARIANT:=no-mrts}"
: "${MODSECURITY_RULESET:=targeted}"
: "${MODSECURITY_SMOKE_CASE:=targeted}"
: "${CRS_SMOKE_CASE:=minimal}"

# OWASP Core Rule Set provenance and release metadata.
#
# CRS_APPROVED_* is deliberately assigned literally rather than derived from
# the environment. CRS_GIT_REF remains release metadata for version reporting;
# fetch-crs.sh must never use it to select a Git object.
CRS_APPROVED_REPO_URL="https://github.com/coreruleset/coreruleset.git"
CRS_APPROVED_COMMIT="55b09f5acfd16413e7b31041100711ceb7adc89c"
CRS_RELEASE_TAG="v4.28.0"
: "${CRS_REPO_URL:=$CRS_APPROVED_REPO_URL}"
: "${CRS_GIT_REF:=$CRS_RELEASE_TAG}"

# CRS paths
: "${CRS_SOURCE_DIR:=${SOURCE_ROOT}/coreruleset}"
: "${CRS_RUNTIME_DIR:=${BUILD_ROOT}/crs}"

# Optional preamble injected before generated local case rules
: "${MODSECURITY_RULE_PREAMBLE_FILE:=}"
MODSECURITY_TARGETED_SMOKE_RULE_FILE="${MODSECURITY_TARGETED_SMOKE_RULE_FILE:-$CONNECTOR_ROOT/common/rules/modsecurity_targeted_smoke.conf}"
MODSECURITY_REQUEST_BODY_SMOKE_RULE_FILE="${MODSECURITY_REQUEST_BODY_SMOKE_RULE_FILE:-$CONNECTOR_ROOT/common/rules/modsecurity_request_body_smoke.conf}"

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
# Optional: external connector repositories are empty by default because this repository
# carries local connector sources unless ALLOW_EXTERNAL_CONNECTOR_REPOS=1.
MODSECURITY_APACHE_REPO_URL="${MODSECURITY_APACHE_REPO_URL:-${MODSECURITY_APACHE_GIT_URL:-}}"
MODSECURITY_APACHE_GIT_URL="${MODSECURITY_APACHE_GIT_URL:-$MODSECURITY_APACHE_REPO_URL}"
MODSECURITY_APACHE_GIT_REF="${MODSECURITY_APACHE_GIT_REF:-$DEFAULT_BRANCH}"

MODSECURITY_NGINX_REPO_URL="${MODSECURITY_NGINX_REPO_URL:-${MODSECURITY_NGINX_GIT_URL:-}}"
MODSECURITY_NGINX_GIT_URL="${MODSECURITY_NGINX_GIT_URL:-$MODSECURITY_NGINX_REPO_URL}"
MODSECURITY_NGINX_GIT_REF="${MODSECURITY_NGINX_GIT_REF:-$DEFAULT_BRANCH}"

HTTPD_VERSION="${HTTPD_VERSION:-2.4.68}"
HTTPD_SOURCE_URL="${HTTPD_SOURCE_URL:-https://downloads.apache.org/httpd/httpd-$HTTPD_VERSION.tar.bz2}"
HTTPD_SHA256="${HTTPD_SHA256:-68c74d4df38c26bed4dfbdb8f3baf1eb532f3872357becc1bba5d136f6b63c06}"
HTTPD_SHA256_URL="${HTTPD_SHA256_URL:-$HTTPD_SOURCE_URL.sha256}"
APR_VERSION="${APR_VERSION:-1.7.6}"
APR_SOURCE_URL="${APR_SOURCE_URL:-https://downloads.apache.org/apr/apr-$APR_VERSION.tar.bz2}"
APR_SHA256="${APR_SHA256:-49030d92d2575da735791b496dc322f3ce5cff9494779ba8cc28c7f46c5deb32}"
APR_SHA256_URL="${APR_SHA256_URL:-$APR_SOURCE_URL.sha256}"
APR_UTIL_VERSION="${APR_UTIL_VERSION:-1.6.3}"
APR_UTIL_SOURCE_URL="${APR_UTIL_SOURCE_URL:-https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2}"
APR_UTIL_SHA256="${APR_UTIL_SHA256:-a41076e3710746326c3945042994ad9a4fcac0ce0277dd8fea076fec3c9772b5}"
APR_UTIL_SHA256_URL="${APR_UTIL_SHA256_URL:-$APR_UTIL_SOURCE_URL.sha256}"
PCRE2_VERSION="${PCRE2_VERSION:-10.47}"
PCRE2_SOURCE_URL="${PCRE2_SOURCE_URL:-https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_VERSION/pcre2-$PCRE2_VERSION.tar.bz2}"
# The literal pin is required before the PCRE2 archive can be extracted.  Use
# the no-colon expansion so an explicitly empty caller override fails closed.
PCRE2_SHA256="${PCRE2_SHA256-47fe8c99461250d42f89e6e8fdaeba9da057855d06eb7fc08d9ca03fd08d7bc7}"
# PCRE2 release assets do not publish a stable per-asset SHA256 URL.  This
# metadata variable is retained for version tooling; it is not an extraction
# verification fallback.
PCRE2_SHA256_URL="${PCRE2_SHA256_URL:-}"

NGINX_SOURCE_MODE="${NGINX_SOURCE_MODE:-github-release}"
NGINX_SOURCE_REPO_URL="${NGINX_SOURCE_REPO_URL:-${NGINX_GITHUB_REPO:-https://github.com/nginx/nginx}}"
NGINX_GITHUB_REPO="${NGINX_GITHUB_REPO:-$NGINX_SOURCE_REPO_URL}"
NGINX_RELEASE_TAG="${NGINX_RELEASE_TAG:-release-1.31.2}"
NGINX_SOURCE_GIT_REF="${NGINX_SOURCE_GIT_REF:-$NGINX_RELEASE_TAG}"
# NGINX Git checkout mode does not use a tarball checksum.
NGINX_SHA256="${NGINX_SHA256:-}"

# Managed NGINX protocol builds are deliberately explicit.  The default keeps
# the established clear-text HTTP/1.1 smoke path unchanged; H2/H3 are opted in
# by selecting a profile at build time.  The H3 profile uses a pinned OpenSSL
# source tree rather than silently relying on whichever system TLS library is
# installed.  The source is only fetched/extracted by prepare-nginx-build.sh
# when that profile is selected.
NGINX_PROTOCOL_PROFILE="${NGINX_PROTOCOL_PROFILE:-h1}"
NGINX_QUIC_TLS_LIBRARY="${NGINX_QUIC_TLS_LIBRARY:-openssl}"
NGINX_QUIC_TLS_VERSION="${NGINX_QUIC_TLS_VERSION:-3.5.1}"
NGINX_QUIC_TLS_SOURCE_URL="${NGINX_QUIC_TLS_SOURCE_URL:-https://github.com/openssl/openssl/releases/download/openssl-3.5.1/openssl-3.5.1.tar.gz}"
NGINX_QUIC_TLS_SOURCE_SHA256="${NGINX_QUIC_TLS_SOURCE_SHA256:-529043b15cffa5f36077a4d0af83f3de399807181d607441d734196d889b641f}"
# Optional explicit archive location, normally supplied by the managed
# runtime-component cache.  An empty value means prepare-nginx-build.sh uses
# the URL basename below NGINX_DOWNLOAD_DIR.
NGINX_QUIC_TLS_ARCHIVE="${NGINX_QUIC_TLS_ARCHIVE:-}"

nginx_protocol_profile_valid() {
    case "${1:-$NGINX_PROTOCOL_PROFILE}" in
        h1|h1-h2|h1-h2-h3-quic) return 0 ;;
        *) return 1 ;;
    esac
}

nginx_protocol_profile_has_http2() {
    case "${1:-$NGINX_PROTOCOL_PROFILE}" in
        h1-h2|h1-h2-h3-quic) return 0 ;;
        *) return 1 ;;
    esac
}

nginx_protocol_profile_has_http3() {
    case "${1:-$NGINX_PROTOCOL_PROFILE}" in
        h1-h2-h3-quic) return 0 ;;
        *) return 1 ;;
    esac
}

nginx_protocol_profile_configure_flags() {
    case "${1:-$NGINX_PROTOCOL_PROFILE}" in
        h1)
            ;;
        h1-h2)
            printf '%s\n' --with-http_ssl_module --with-http_v2_module
            ;;
        h1-h2-h3-quic)
            printf '%s\n' --with-http_ssl_module --with-http_v2_module --with-http_v3_module
            ;;
        *)
            return 1
            ;;
    esac
}

HAPROXY_VERSION="${HAPROXY_VERSION:-3.2.21}"
HAPROXY_SOURCE_URL="${HAPROXY_SOURCE_URL:-https://www.haproxy.org/download/3.2/src/haproxy-$HAPROXY_VERSION.tar.gz}"
HAPROXY_SHA256_URL="${HAPROXY_SHA256_URL:-$HAPROXY_SOURCE_URL.sha256}"
HAPROXY_SHA256="${HAPROXY_SHA256:-0cb8818a26c5f888e0cb1c40f1b3acb9fb952527d1733f769ce688fedd680339}"
HAPROXY_SOURCE_ROOT="${HAPROXY_SOURCE_ROOT:-$SOURCE_ROOT/haproxy}"
HAPROXY_DOWNLOAD_DIR="${HAPROXY_DOWNLOAD_DIR:-$HAPROXY_SOURCE_ROOT/downloads}"
HAPROXY_SOURCE_DIR="${HAPROXY_SOURCE_DIR:-$HAPROXY_SOURCE_ROOT/haproxy-$HAPROXY_VERSION}"
HAPROXY_RUNTIME_BUILD_DIR="${HAPROXY_RUNTIME_BUILD_DIR:-$BUILD_ROOT/haproxy-runtime-build}"
HAPROXY_RUNTIME_BUILD_WORKTREE="${HAPROXY_RUNTIME_BUILD_WORKTREE:-$HAPROXY_RUNTIME_BUILD_DIR/worktree}"
HAPROXY_RUNTIME_DIR="${HAPROXY_RUNTIME_DIR:-$BUILD_ROOT/haproxy-runtime/haproxy}"
HAPROXY_BIN="${HAPROXY_BIN:-$HAPROXY_RUNTIME_DIR/sbin/haproxy}"

GO_FTW_SOURCE_URL="${GO_FTW_SOURCE_URL:-https://github.com/coreruleset/go-ftw}"
GO_FTW_PROMPT_EXPECTED_LATEST="${GO_FTW_PROMPT_EXPECTED_LATEST:-v2.2.0}"
GO_FTW_GIT_REF="${GO_FTW_GIT_REF:-$GO_FTW_PROMPT_EXPECTED_LATEST}"
GO_FTW_BIN="${GO_FTW_BIN:-go-ftw}"

ALBEDO_SOURCE_URL="${ALBEDO_SOURCE_URL:-https://github.com/coreruleset/albedo}"
ALBEDO_PROMPT_EXPECTED_LATEST="${ALBEDO_PROMPT_EXPECTED_LATEST:-v0.3.0}"
ALBEDO_GIT_REF="${ALBEDO_GIT_REF:-$ALBEDO_PROMPT_EXPECTED_LATEST}"
ALBEDO_BIN="${ALBEDO_BIN:-albedo}"

EXPAT_SOURCE_URL="${EXPAT_SOURCE_URL:-https://github.com/libexpat/libexpat}"
EXPAT_GIT_REF="${EXPAT_GIT_REF:-master}"
EXPAT_GIT_URL="${EXPAT_GIT_URL:-$EXPAT_SOURCE_URL}"
EXPAT_PROMPT_EXPECTED_LATEST="${EXPAT_PROMPT_EXPECTED_LATEST:-$EXPAT_GIT_REF}"

# Optional tool override variables intentionally default to empty and are resolved by probes.
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

ci_is_https_url() {
    case "$1" in
        https://*) return 0 ;;
        *) return 1 ;;
    esac
}

ci_require_https_url() {
    ci_url=$1
    ci_label=${2:-url}
    if ci_is_https_url "$ci_url"; then
        return 0
    fi
    ci_blocked "$ci_label must use https:// only: $ci_url"
    return 77
}

ci_require_https_url_if_set() {
    ci_url=$1
    ci_label=${2:-url}
    if [ -z "$ci_url" ]; then
        return 0
    fi
    ci_require_https_url "$ci_url" "$ci_label"
}

ci_require_https_github_repo_url() {
    ci_url=$1
    ci_label=${2:-github repo url}

    case "$ci_url" in
        https://github.com/*) ;;
        *)
            ci_blocked "$ci_label must use https://github.com/... only: $ci_url"
            return 77
            ;;
    esac

    case "$ci_url" in
        *" "*|*"	"*|*"#"*|*"?"*)
            ci_blocked "$ci_label contains invalid characters: $ci_url"
            return 77
            ;;
    esac

    ci_repo=${ci_url#https://github.com/}
    ci_repo=${ci_repo%.git}
    ci_repo=${ci_repo%/}
    case "$ci_repo" in
        */*/*|/*|*/)
            ci_blocked "$ci_label must be https://github.com/owner/repo only: $ci_url"
            return 77
            ;;
        */*)
            ci_owner=${ci_repo%%/*}
            ci_name=${ci_repo#*/}
            if [ -n "$ci_owner" ] && [ -n "$ci_name" ]; then
                return 0
            fi
            ;;
        *) ;;
    esac

    ci_blocked "$ci_label must be https://github.com/owner/repo only: $ci_url"
    return 77
}

ci_require_https_github_repo_url_if_set() {
    ci_url=$1
    ci_label=${2:-github repo url}
    if [ -z "$ci_url" ]; then
        return 0
    fi
    ci_require_https_github_repo_url "$ci_url" "$ci_label"
}

ci_validate_safe_ref_config() {
    for ci_ref_pair in \
        "CRS_GIT_REF:$CRS_GIT_REF" \
        "MODSECURITY_GIT_REF:$MODSECURITY_GIT_REF" \
        "MODSECURITY_V3_GIT_REF:$MODSECURITY_V3_GIT_REF" \
        "MODSECURITY_APACHE_GIT_REF:$MODSECURITY_APACHE_GIT_REF" \
        "MODSECURITY_NGINX_GIT_REF:$MODSECURITY_NGINX_GIT_REF" \
        "NGINX_RELEASE_TAG:$NGINX_RELEASE_TAG" \
        "NGINX_SOURCE_GIT_REF:$NGINX_SOURCE_GIT_REF" \
        "GO_FTW_GIT_REF:$GO_FTW_GIT_REF" \
        "ALBEDO_GIT_REF:$ALBEDO_GIT_REF" \
        "EXPAT_GIT_REF:$EXPAT_GIT_REF"
    do
        ci_ref_label=${ci_ref_pair%%:*}
        ci_ref_value=${ci_ref_pair#*:}
        ci_require_safe_ref "$ci_ref_value" "$ci_ref_label" || return 77
    done
    return 0
}

ci_validate_https_runtime_url_config() {
    ci_validate_safe_ref_config || return 77
    ci_require_https_github_repo_url "$CRS_REPO_URL" CRS_REPO_URL || return 77
    ci_require_https_github_repo_url "$MODSECURITY_REPO_URL" MODSECURITY_REPO_URL || return 77
    ci_require_https_github_repo_url "$MODSECURITY_V3_GIT_URL" MODSECURITY_V3_GIT_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_APACHE_REPO_URL" MODSECURITY_APACHE_REPO_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_APACHE_GIT_URL" MODSECURITY_APACHE_GIT_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_NGINX_REPO_URL" MODSECURITY_NGINX_REPO_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_NGINX_GIT_URL" MODSECURITY_NGINX_GIT_URL || return 77
    ci_require_https_github_repo_url "$NGINX_SOURCE_REPO_URL" NGINX_SOURCE_REPO_URL || return 77
    ci_require_https_github_repo_url "$NGINX_GITHUB_REPO" NGINX_GITHUB_REPO || return 77
    ci_require_https_url "$NGINX_QUIC_TLS_SOURCE_URL" NGINX_QUIC_TLS_SOURCE_URL || return 77
    ci_require_https_github_repo_url "$GO_FTW_SOURCE_URL" GO_FTW_SOURCE_URL || return 77
    ci_require_https_github_repo_url "$ALBEDO_SOURCE_URL" ALBEDO_SOURCE_URL || return 77
    ci_require_https_github_repo_url "$EXPAT_SOURCE_URL" EXPAT_SOURCE_URL || return 77
    ci_require_https_url "$ENVOY_SOURCE_URL" ENVOY_SOURCE_URL || return 77
    ci_require_https_url "$ENVOY_INSTALL_DOCS_URL" ENVOY_INSTALL_DOCS_URL || return 77
    ci_require_https_url_if_set "$ENVOY_DOWNLOAD_URL" ENVOY_DOWNLOAD_URL || return 77
    ci_require_https_url_if_set "$ENVOY_SHA256_URL" ENVOY_SHA256_URL || return 77
    ci_require_https_url "$TRAEFIK_SOURCE_URL" TRAEFIK_SOURCE_URL || return 77
    ci_require_https_url "$TRAEFIK_INSTALL_DOCS_URL" TRAEFIK_INSTALL_DOCS_URL || return 77
    ci_require_https_url_if_set "$TRAEFIK_DOWNLOAD_URL" TRAEFIK_DOWNLOAD_URL || return 77
    ci_require_https_url_if_set "$TRAEFIK_SHA256_URL" TRAEFIK_SHA256_URL || return 77
    ci_require_https_url "$LIGHTTPD_SOURCE_URL" LIGHTTPD_SOURCE_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_RELEASE_INDEX_URL" LIGHTTPD_RELEASE_INDEX_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_LATEST_URL" LIGHTTPD_LATEST_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_DOWNLOAD_URL" LIGHTTPD_DOWNLOAD_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_SHA256_URL" LIGHTTPD_SHA256_URL || return 77
    ci_require_https_url "$HAPROXY_SOURCE_URL" HAPROXY_SOURCE_URL || return 77
    ci_require_https_url "$HTTPD_SOURCE_URL" HTTPD_SOURCE_URL || return 77
    ci_require_https_url "$APR_SOURCE_URL" APR_SOURCE_URL || return 77
    ci_require_https_url "$APR_UTIL_SOURCE_URL" APR_UTIL_SOURCE_URL || return 77
    ci_require_https_url "$PCRE2_SOURCE_URL" PCRE2_SOURCE_URL || return 77
    return 0
}

combine_rule_preambles() {
    first=$1
    second=$2
    label=${3:-combined}
    if [ -z "$first" ]; then
        printf '%s\n' "$second"
        return 0
    fi
    if [ -z "$second" ] || [ "$first" = "$second" ]; then
        printf '%s\n' "$first"
        return 0
    fi
    combined="$BUILD_ROOT/preambles/$label.load"
    assert_safe_runtime_path "$BUILD_ROOT/preambles" "rule preamble directory" || return 77
    assert_not_system_path_for_write "$combined" "combined rule preamble" || return 77
    mkdir -p "$BUILD_ROOT/preambles"
    {
        printf 'Include "%s"\n' "$first"
        printf 'Include "%s"\n' "$second"
    } > "$combined"
    printf '%s\n' "$combined"
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

ci_command_path() {
    ci_cmd=$1
    [ -n "$ci_cmd" ] || return 1
    ci_cmd_path=$(command -v "$ci_cmd" 2>/dev/null || true)
    if [ -n "$ci_cmd_path" ]; then
        printf '%s\n' "$ci_cmd_path"
        return 0
    fi
    if [ -x "$ci_cmd" ]; then
        printf '%s\n' "$ci_cmd"
        return 0
    fi
    return 1
}

skip_blocked() {
    echo "BLOCKED: $*" >&2
    exit 77
}

is_local_run() {
    [ "${GITHUB_ACTIONS:-}" = "true" ] && return 1
    [ "${CI:-}" = "true" ] && return 1
    return 0
}

ci_fail_local_provisioning() {
    echo "FAIL: $*" >&2
    exit 1
}

framework_prepare_runtime_components() {
    if ! is_local_run; then
        return 77
    fi

    ci_prepare_script="${CONNECTOR_ROOT:-}/ci/provisioning/components/prepare-runtime-components.py"
    if [ ! -f "$ci_prepare_script" ]; then
        echo "FAIL: missing local runtime provisioning helper: $ci_prepare_script" >&2
        return 1
    fi

    ci_prepare_python=$(ci_python)
    "$ci_prepare_python" "$ci_prepare_script" \
        --connector-root "$CONNECTOR_ROOT" \
        --framework-root "$FRAMEWORK_ROOT" \
        --cache-root "$CONNECTOR_COMPONENT_CACHE" \
        --output-root "$CONNECTOR_ROOT" \
        --build-root "$BUILD_ROOT" \
        --native-root "${MRTS_NATIVE_ROOT:-$BUILD_ROOT/mrts-native}" >&2
}

ci_runtime_version_matches() {
    ci_expected_runtime_version=$1
    ci_runtime_version_text=$2
    [ -n "$ci_expected_runtime_version" ] || return 1

    case "$ci_runtime_version_text" in
        "$ci_expected_runtime_version"|\
        "$ci_expected_runtime_version"[!0-9.]*|\
        *[!0-9.]"$ci_expected_runtime_version"|\
        *[!0-9.]"$ci_expected_runtime_version"[!0-9.]*) return 0 ;;
        *) return 1 ;;
    esac
}

ci_runtime_binary_matches_version() {
    ci_runtime_binary=$1
    ci_runtime_version=$2
    ci_runtime_version_arg=$3
    [ -f "$ci_runtime_binary" ] && [ -x "$ci_runtime_binary" ] || return 1

    ci_runtime_version_output=$("$ci_runtime_binary" "$ci_runtime_version_arg" 2>&1 || true)
    ci_runtime_version_matches "$ci_runtime_version" "$ci_runtime_version_output"
}

ci_stage_matching_runtime_binary() {
    ci_runtime_name=$1
    ci_runtime_version=$2
    ci_runtime_version_arg=$3
    ci_runtime_destination=$4
    ci_runtime_system_path=$(command -v "$ci_runtime_name" 2>/dev/null || true)
    [ -n "$ci_runtime_system_path" ] && [ -x "$ci_runtime_system_path" ] || return 1

    ci_runtime_binary_matches_version \
        "$ci_runtime_system_path" "$ci_runtime_version" "$ci_runtime_version_arg" || return 1

    assert_safe_runtime_path "$(dirname "$ci_runtime_destination")" "${ci_runtime_name} staging directory" || return 1
    mkdir -p "$(dirname "$ci_runtime_destination")"
    cp "$ci_runtime_system_path" "$ci_runtime_destination"
    chmod 0755 "$ci_runtime_destination"
    printf '%s\n' "$ci_runtime_destination"
}

envoy_build_paths() {
    export ENVOY_COMPONENT_ROOT ENVOY_SOURCE_ROOT ENVOY_BUILD_ROOT ENVOY_BIN
    printf 'ENVOY_COMPONENT_ROOT=%s\n' "$ENVOY_COMPONENT_ROOT"
    printf 'ENVOY_SOURCE_ROOT=%s\n' "$ENVOY_SOURCE_ROOT"
    printf 'ENVOY_BUILD_ROOT=%s\n' "$ENVOY_BUILD_ROOT"
    printf 'ENVOY_BIN=%s\n' "$ENVOY_BIN"
}

traefik_build_paths() {
    export TRAEFIK_COMPONENT_ROOT TRAEFIK_SOURCE_ROOT TRAEFIK_BUILD_ROOT TRAEFIK_BIN
    printf 'TRAEFIK_COMPONENT_ROOT=%s\n' "$TRAEFIK_COMPONENT_ROOT"
    printf 'TRAEFIK_SOURCE_ROOT=%s\n' "$TRAEFIK_SOURCE_ROOT"
    printf 'TRAEFIK_BUILD_ROOT=%s\n' "$TRAEFIK_BUILD_ROOT"
    printf 'TRAEFIK_BIN=%s\n' "$TRAEFIK_BIN"
}

lighttpd_build_paths() {
    export LIGHTTPD_COMPONENT_ROOT LIGHTTPD_SOURCE_DIR LIGHTTPD_BUILD_ROOT
    export LIGHTTPD_INCLUDE_DIR LIGHTTPD_CONNECTOR_BUILD_ROOT LIGHTTPD_MODULE_DIR LIGHTTPD_BIN
    printf 'LIGHTTPD_COMPONENT_ROOT=%s\n' "$LIGHTTPD_COMPONENT_ROOT"
    printf 'LIGHTTPD_SOURCE_DIR=%s\n' "$LIGHTTPD_SOURCE_DIR"
    printf 'LIGHTTPD_BUILD_ROOT=%s\n' "$LIGHTTPD_BUILD_ROOT"
    printf 'LIGHTTPD_INCLUDE_DIR=%s\n' "$LIGHTTPD_INCLUDE_DIR"
    printf 'LIGHTTPD_CONNECTOR_BUILD_ROOT=%s\n' "$LIGHTTPD_CONNECTOR_BUILD_ROOT"
    printf 'LIGHTTPD_MODULE_DIR=%s\n' "$LIGHTTPD_MODULE_DIR"
    printf 'LIGHTTPD_BIN=%s\n' "$LIGHTTPD_BIN"
}

require_or_provision_envoy() {
    envoy_build_paths >/dev/null
    if [ -x "$ENVOY_BIN" ]; then
        if ci_runtime_binary_matches_version "$ENVOY_BIN" "$ENVOY_VERSION" --version; then
            printf '%s\n' "$ENVOY_BIN"
            return 0
        fi
        echo "FAIL: Envoy binary does not match pinned version $ENVOY_VERSION: $ENVOY_BIN" >&2
        return 1
    fi
    ci_staged_runtime=$(ci_stage_matching_runtime_binary envoy "$ENVOY_VERSION" --version "$ENVOY_COMPONENT_ROOT/bin/envoy" 2>/dev/null || true)
    if [ -n "$ci_staged_runtime" ]; then
        ENVOY_BIN=$ci_staged_runtime
        export ENVOY_BIN
        printf '%s\n' "$ENVOY_BIN"
        return 0
    fi
    if ALLOW_RUNTIME_DOWNLOADS=1 FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-envoy-runtime.sh" >&2 \
        && ci_runtime_binary_matches_version "$ENVOY_BIN" "$ENVOY_VERSION" --version; then
        printf '%s\n' "$ENVOY_BIN"
        return 0
    fi
    echo "FAIL: Envoy provisioning did not produce $ENVOY_BIN" >&2
    return 1
}

require_or_provision_traefik() {
    traefik_build_paths >/dev/null
    if [ -x "$TRAEFIK_BIN" ]; then
        if ci_runtime_binary_matches_version "$TRAEFIK_BIN" "$TRAEFIK_VERSION" version; then
            printf '%s\n' "$TRAEFIK_BIN"
            return 0
        fi
        echo "FAIL: Traefik binary does not match pinned version $TRAEFIK_VERSION: $TRAEFIK_BIN" >&2
        return 1
    fi
    ci_staged_runtime=$(ci_stage_matching_runtime_binary traefik "$TRAEFIK_VERSION" version "$TRAEFIK_COMPONENT_ROOT/bin/traefik" 2>/dev/null || true)
    if [ -n "$ci_staged_runtime" ]; then
        TRAEFIK_BIN=$ci_staged_runtime
        export TRAEFIK_BIN
        printf '%s\n' "$TRAEFIK_BIN"
        return 0
    fi
    if ALLOW_RUNTIME_DOWNLOADS=1 FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-traefik-runtime.sh" >&2 \
        && ci_runtime_binary_matches_version "$TRAEFIK_BIN" "$TRAEFIK_VERSION" version; then
        printf '%s\n' "$TRAEFIK_BIN"
        return 0
    fi
    echo "FAIL: Traefik provisioning did not produce $TRAEFIK_BIN" >&2
    return 1
}

require_or_provision_lighttpd() {
    lighttpd_build_paths >/dev/null
    if [ -x "$LIGHTTPD_BIN" ]; then
        if ! ci_runtime_binary_matches_version "$LIGHTTPD_BIN" "$LIGHTTPD_VERSION" -v; then
            echo "FAIL: lighttpd binary does not match pinned version $LIGHTTPD_VERSION: $LIGHTTPD_BIN" >&2
            return 1
        fi
    else
        ci_staged_runtime=$(ci_stage_matching_runtime_binary lighttpd "$LIGHTTPD_VERSION" -v "$LIGHTTPD_COMPONENT_ROOT/bin/lighttpd" 2>/dev/null || true)
        if [ -n "$ci_staged_runtime" ]; then
            LIGHTTPD_BIN=$ci_staged_runtime
            export LIGHTTPD_BIN
        fi
    fi
    if [ -x "$LIGHTTPD_BIN" ] && [ -f "$LIGHTTPD_INCLUDE_DIR/plugin.h" ]; then
        printf '%s\n' "$LIGHTTPD_BIN"
        return 0
    fi
    if ALLOW_RUNTIME_DOWNLOADS=1 ALLOW_RUNTIME_BUILDS=1 \
        LIGHTTPD_BIN= \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-lighttpd-runtime.sh" >&2 \
        && ci_runtime_binary_matches_version "$LIGHTTPD_BIN" "$LIGHTTPD_VERSION" -v \
        && [ -f "$LIGHTTPD_INCLUDE_DIR/plugin.h" ]; then
        printf '%s\n' "$LIGHTTPD_BIN"
        return 0
    fi
    echo "FAIL: lighttpd provisioning did not produce binary and headers" >&2
    return 1
}

require_command_or_blocked() {
    ci_required_cmd=$1
    ci_required_reason=${2:-missing required command: $ci_required_cmd}

    ci_command_path "$ci_required_cmd" >/dev/null 2>&1 || skip_blocked "$ci_required_reason"
    return 0
}

framework_apxs_has_usable_headers() {
    ci_apxs_candidate=$1
    [ -n "$ci_apxs_candidate" ] || return 1
    [ -x "$ci_apxs_candidate" ] || return 1
    ci_apxs_includedir=$("$ci_apxs_candidate" -q INCLUDEDIR 2>/dev/null || true)
    [ -n "$ci_apxs_includedir" ] || return 1
    [ -f "$ci_apxs_includedir/httpd.h" ] || return 1
    return 0
}

framework_find_apxs() {
    for ci_apxs_candidate in "${APXS_BIN:-}" "${APXS:-}"; do
        if [ -z "$ci_apxs_candidate" ]; then
            continue
        fi
        ci_apxs_path=$(ci_command_path "$ci_apxs_candidate" 2>/dev/null || true)
        if framework_apxs_has_usable_headers "$ci_apxs_path"; then
            printf '%s\n' "$ci_apxs_path"
            return 0
        fi
    done

    ci_apxs_path=$(ci_find_bin_multi $CI_APXS_BIN_CANDIDATES 2>/dev/null || true)
    if framework_apxs_has_usable_headers "$ci_apxs_path"; then
        printf '%s\n' "$ci_apxs_path"
        return 0
    fi

    for ci_apxs_candidate in \
        "$CONNECTOR_COMPONENT_CACHE"/builds/connectors/apache/*/httpd/bin/apxs \
        "$CONNECTOR_COMPONENT_CACHE"/builds/connectors/apache/*/httpd/bin/apxs2 \
        "$CONNECTOR_COMPONENT_CACHE"/builds/connectors/apache/*/build/httpd/support/apxs \
        "$BUILD_ROOT"/apache-build/httpd/bin/apxs \
        "$BUILD_ROOT"/apache-build/build/httpd/support/apxs; do
        ci_apxs_path=$(ci_command_path "$ci_apxs_candidate" 2>/dev/null || true)
        if framework_apxs_has_usable_headers "$ci_apxs_path"; then
            printf '%s\n' "$ci_apxs_path"
            return 0
        fi
    done

    return 1
}

find_apxs_or_blocked() {
    ci_apxs_path=$(framework_find_apxs 2>/dev/null || true)
    if [ -n "$ci_apxs_path" ]; then
        printf '%s\n' "$ci_apxs_path"
        return 0
    fi

    skip_blocked "missing apxs/apxs2 for Apache connector checks"
}

require_or_provision_apxs() {
    ci_apxs_path=$(framework_find_apxs 2>/dev/null || true)
    if [ -n "$ci_apxs_path" ]; then
        printf '%s\n' "$ci_apxs_path"
        return 0
    fi

    if ! is_local_run; then
        skip_blocked "missing apxs/apxs2 for Apache connector checks"
    fi

    ci_provision_rc=0
    if framework_prepare_runtime_components; then
        :
    else
        ci_provision_rc=$?
    fi
    ci_apxs_path=$(framework_find_apxs 2>/dev/null || true)
    if [ -n "$ci_apxs_path" ]; then
        printf '%s\n' "$ci_apxs_path"
        return 0
    fi

    ci_fail_local_provisioning "local Apache/APXS provisioning did not produce apxs/apxs2 (prepare-runtime-components rc=$ci_provision_rc)"
}

ci_modsecurity_include_flags() {
    ci_modsecurity_flags=
    ci_modsecurity_found=0

    for ci_modsecurity_include in ${MODSECURITY_INCLUDE:-} ${MODSECURITY_INCLUDE_DIR:-} ${MODSECURITY_INC:-} ${V3INCLUDE:-}; do
        case "$ci_modsecurity_include" in
            -I*)
                ci_modsecurity_dir=${ci_modsecurity_include#-I}
                ci_modsecurity_flag=$ci_modsecurity_include
                ;;
            *)
                ci_modsecurity_dir=$ci_modsecurity_include
                ci_modsecurity_flag="-I$ci_modsecurity_dir"
                ;;
        esac
        if [ -n "$ci_modsecurity_dir" ] && [ -f "$ci_modsecurity_dir/modsecurity/modsecurity.h" ]; then
            ci_modsecurity_flags="$ci_modsecurity_flags $ci_modsecurity_flag"
            ci_modsecurity_found=1
        fi
    done

    if [ "$ci_modsecurity_found" != 1 ]; then
        for ci_modsecurity_dir in \
            "$CONNECTOR_COMPONENT_CACHE"/prefix/modsecurity/*/include \
            "$CONNECTOR_COMPONENT_CACHE"/sources/ModSecurity_V3/headers \
            "$CONNECTOR_COMPONENT_CACHE"/builds/modsecurity/*/source/headers \
            "$MODSECURITY_SOURCE_DIR"/headers \
            /usr/include \
            /usr/local/include; do
            if [ -f "$ci_modsecurity_dir/modsecurity/modsecurity.h" ]; then
                ci_modsecurity_flags="$ci_modsecurity_flags -I$ci_modsecurity_dir"
                ci_modsecurity_found=1
                break
            fi
        done
    fi

    if [ "$ci_modsecurity_found" = 1 ]; then
        printf '%s\n' "$ci_modsecurity_flags"
        return 0
    fi

    return 1
}

modsecurity_include_flags_or_blocked() {
    ci_modsecurity_flags=$(ci_modsecurity_include_flags 2>/dev/null || true)
    if [ -n "$ci_modsecurity_flags" ]; then
        printf '%s\n' "$ci_modsecurity_flags"
        return 0
    fi

    skip_blocked "missing libmodsecurity headers"
}

modsecurity_include_flags_or_provision() {
    ci_modsecurity_flags=$(ci_modsecurity_include_flags 2>/dev/null || true)
    if [ -n "$ci_modsecurity_flags" ]; then
        printf '%s\n' "$ci_modsecurity_flags"
        return 0
    fi

    if ! is_local_run; then
        skip_blocked "missing libmodsecurity headers"
    fi

    ci_provision_rc=0
    if framework_prepare_runtime_components; then
        :
    else
        ci_provision_rc=$?
    fi
    ci_modsecurity_flags=$(ci_modsecurity_include_flags 2>/dev/null || true)
    if [ -n "$ci_modsecurity_flags" ]; then
        printf '%s\n' "$ci_modsecurity_flags"
        return 0
    fi

    ci_fail_local_provisioning "local libmodsecurity provisioning did not produce headers (prepare-runtime-components rc=$ci_provision_rc)"
}

require_modsecurity_headers_or_blocked() {
    modsecurity_include_flags_or_blocked >/dev/null
    return 0
}

require_or_provision_modsecurity_headers() {
    modsecurity_include_flags_or_provision >/dev/null
    return 0
}

ci_nginx_include_dir_flags() {
    ci_nginx_dir=$1
    [ -n "$ci_nginx_dir" ] && [ -d "$ci_nginx_dir" ] || return 1

    if [ -f "$ci_nginx_dir/ngx_config.h" ] \
        && [ -f "$ci_nginx_dir/ngx_core.h" ] \
        && [ -f "$ci_nginx_dir/ngx_http.h" ]; then
        printf '%s\n' "-I$ci_nginx_dir"
        return 0
    fi

    if [ -f "$ci_nginx_dir/nginx/ngx_config.h" ] \
        && [ -f "$ci_nginx_dir/nginx/ngx_core.h" ] \
        && [ -f "$ci_nginx_dir/nginx/ngx_http.h" ]; then
        printf '%s\n' "-I$ci_nginx_dir/nginx"
        return 0
    fi

    return 1
}

ci_nginx_source_dir_flags() {
    ci_nginx_dir=$1
    [ -n "$ci_nginx_dir" ] && [ -d "$ci_nginx_dir" ] || return 1

    if [ -f "$ci_nginx_dir/src/core/ngx_config.h" ] \
        && [ -f "$ci_nginx_dir/src/core/ngx_core.h" ] \
        && [ -f "$ci_nginx_dir/src/http/ngx_http.h" ] \
        && [ -f "$ci_nginx_dir/objs/ngx_auto_config.h" ]; then
        printf '%s\n' "-I$ci_nginx_dir/src/core -I$ci_nginx_dir/src/http -I$ci_nginx_dir/src/http/modules -I$ci_nginx_dir/src/http/v2 -I$ci_nginx_dir/src/http/v3 -I$ci_nginx_dir/src/event -I$ci_nginx_dir/src/os/unix -I$ci_nginx_dir/objs"
        return 0
    fi

    return 1
}

ci_nginx_include_flags() {
    ci_nginx_flags=
    ci_nginx_found=0

    for ci_nginx_dir in "${NGINX_INCLUDE_DIR:-}" "${NGINX_INCLUDE:-}" /usr/include/nginx /usr/local/include/nginx /usr/include /usr/local/include; do
        ci_nginx_dir_flags=$(ci_nginx_include_dir_flags "$ci_nginx_dir" 2>/dev/null || true)
        if [ -n "$ci_nginx_dir_flags" ]; then
            ci_nginx_flags="$ci_nginx_flags $ci_nginx_dir_flags"
            ci_nginx_found=1
            break
        fi
    done

    if [ "$ci_nginx_found" != 1 ]; then
        for ci_nginx_dir in \
            "${NGINX_SOURCE_DIR:-}" \
            "${NGINX_SRC:-}" \
            "${MODSECURITY_NGINX_SOURCE_DIR:-}" \
            "$CONNECTOR_COMPONENT_CACHE"/builds/connectors/nginx/*/build/nginx-src \
            "$CONNECTOR_COMPONENT_CACHE"/builds/connectors/nginx/*/nginx-src \
            "$BUILD_ROOT"/nginx-build/nginx-src \
            "$SOURCE_ROOT"/nginx/nginx-*; do
            ci_nginx_dir_flags=$(ci_nginx_source_dir_flags "$ci_nginx_dir" 2>/dev/null || true)
            if [ -n "$ci_nginx_dir_flags" ]; then
                ci_nginx_flags="$ci_nginx_flags $ci_nginx_dir_flags"
                ci_nginx_found=1
                break
            fi
        done
    fi

    if [ "$ci_nginx_found" = 1 ]; then
        printf '%s\n' "$ci_nginx_flags"
        return 0
    fi

    return 1
}

nginx_include_flags_or_blocked() {
    ci_nginx_flags=$(ci_nginx_include_flags 2>/dev/null || true)
    if [ -n "$ci_nginx_flags" ]; then
        printf '%s\n' "$ci_nginx_flags"
        return 0
    fi

    skip_blocked "missing NGINX headers/source for NGINX connector C checks"
}

require_or_provision_nginx_headers() {
    ci_nginx_flags=$(ci_nginx_include_flags 2>/dev/null || true)
    if [ -n "$ci_nginx_flags" ]; then
        printf '%s\n' "$ci_nginx_flags"
        return 0
    fi

    if ! is_local_run; then
        skip_blocked "missing NGINX headers/source for NGINX connector C checks"
    fi

    ci_provision_rc=0
    if framework_prepare_runtime_components; then
        :
    else
        ci_provision_rc=$?
    fi
    ci_nginx_flags=$(ci_nginx_include_flags 2>/dev/null || true)
    if [ -n "$ci_nginx_flags" ]; then
        printf '%s\n' "$ci_nginx_flags"
        return 0
    fi

    ci_fail_local_provisioning "local NGINX provisioning did not produce headers/source (prepare-runtime-components rc=$ci_provision_rc)"
}

require_nginx_headers_or_blocked() {
    nginx_include_flags_or_blocked >/dev/null
    return 0
}

ci_haproxy_include_dir_flags() {
    ci_haproxy_dir=$1
    [ -n "$ci_haproxy_dir" ] && [ -d "$ci_haproxy_dir" ] || return 1

    if [ -f "$ci_haproxy_dir/haproxy/api.h" ] \
        || [ -f "$ci_haproxy_dir/common/cfgparse.h" ] \
        || [ -f "$ci_haproxy_dir/types/global.h" ]; then
        printf '%s\n' "-Dtypeof=__typeof__ -I$ci_haproxy_dir"
        return 0
    fi

    if [ -f "$ci_haproxy_dir/api.h" ]; then
        ci_haproxy_parent=$(CDPATH= cd -- "$ci_haproxy_dir/.." 2>/dev/null && pwd)
        printf '%s\n' "-Dtypeof=__typeof__ -I$ci_haproxy_parent"
        return 0
    fi

    return 1
}

ci_haproxy_source_dir_flags() {
    ci_haproxy_dir=$1
    [ -n "$ci_haproxy_dir" ] && [ -d "$ci_haproxy_dir" ] || return 1

    if [ -f "$ci_haproxy_dir/include/haproxy/api.h" ] \
        || [ -f "$ci_haproxy_dir/include/common/cfgparse.h" ] \
        || [ -f "$ci_haproxy_dir/include/types/global.h" ]; then
        printf '%s\n' "-Dtypeof=__typeof__ -I$ci_haproxy_dir/include -I$ci_haproxy_dir/src"
        return 0
    fi

    return 1
}

ci_haproxy_include_flags() {
    ci_haproxy_flags=
    ci_haproxy_found=0

    for ci_haproxy_dir in "${HAPROXY_INCLUDE_DIR:-}" "${HAPROXY_INCLUDE:-}" /usr/include /usr/local/include /usr/include/haproxy /usr/local/include/haproxy; do
        ci_haproxy_dir_flags=$(ci_haproxy_include_dir_flags "$ci_haproxy_dir" 2>/dev/null || true)
        if [ -n "$ci_haproxy_dir_flags" ]; then
            ci_haproxy_flags="$ci_haproxy_flags $ci_haproxy_dir_flags"
            ci_haproxy_found=1
            break
        fi
    done

    if [ "$ci_haproxy_found" != 1 ]; then
        for ci_haproxy_dir in \
            "${HAPROXY_SOURCE_DIR:-}" \
            "${HAPROXY_SRC:-}" \
            "${MODSECURITY_HAPROXY_SOURCE_DIR:-}" \
            "$CONNECTOR_COMPONENT_CACHE"/sources/haproxy/haproxy-* \
            "$CONNECTOR_COMPONENT_CACHE"/builds/connectors/haproxy/*/haproxy-runtime-build/worktree \
            "$BUILD_ROOT"/haproxy-runtime-build/worktree \
            "$SOURCE_ROOT"/haproxy/haproxy-*; do
            ci_haproxy_dir_flags=$(ci_haproxy_source_dir_flags "$ci_haproxy_dir" 2>/dev/null || true)
            if [ -n "$ci_haproxy_dir_flags" ]; then
                ci_haproxy_flags="$ci_haproxy_flags $ci_haproxy_dir_flags"
                ci_haproxy_found=1
                break
            fi
        done
    fi

    if [ "$ci_haproxy_found" = 1 ]; then
        printf '%s\n' "$ci_haproxy_flags"
        return 0
    fi

    return 1
}

haproxy_include_flags_or_blocked() {
    ci_haproxy_flags=$(ci_haproxy_include_flags 2>/dev/null || true)
    if [ -n "$ci_haproxy_flags" ]; then
        printf '%s\n' "$ci_haproxy_flags"
        return 0
    fi

    skip_blocked "missing HAProxy headers/source for HAProxy connector C checks"
}

require_or_provision_haproxy_headers() {
    ci_haproxy_flags=$(ci_haproxy_include_flags 2>/dev/null || true)
    if [ -n "$ci_haproxy_flags" ]; then
        printf '%s\n' "$ci_haproxy_flags"
        return 0
    fi

    if ! is_local_run; then
        skip_blocked "missing HAProxy headers/source for HAProxy connector C checks"
    fi

    ci_provision_rc=0
    if framework_prepare_runtime_components; then
        :
    else
        ci_provision_rc=$?
    fi
    ci_haproxy_flags=$(ci_haproxy_include_flags 2>/dev/null || true)
    if [ -n "$ci_haproxy_flags" ]; then
        printf '%s\n' "$ci_haproxy_flags"
        return 0
    fi

    ci_fail_local_provisioning "local HAProxy provisioning did not produce headers/source (prepare-runtime-components rc=$ci_provision_rc)"
}

require_haproxy_headers_or_blocked() {
    haproxy_include_flags_or_blocked >/dev/null
    return 0
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
    ci_abs_path=$1
    ci_abs_label=$2
    case "$ci_abs_path" in
        /*) return 0 ;;
        *) ci_blocked "$ci_abs_label must be absolute: $ci_abs_path"; return 77 ;;
    esac
    return 0
}

ci_path_is_configured_project_path() {
    ci_project_path=$1
    for ci_project_root in "${REPO_ROOT:-}" "${CONNECTOR_ROOT:-}" "${FRAMEWORK_ROOT:-}"; do
        [ -n "$ci_project_root" ] || continue
        case "$ci_project_path" in
            "$ci_project_root"|"$ci_project_root"/*) return 0 ;;
        esac
    done
    return 1
}

ci_path_is_system_path() {
    ci_path_value=$1
    if ci_path_is_configured_project_path "$ci_path_value"; then
        return 1
    fi
    case "$ci_path_value" in
        /var/tmp|/var/tmp/*)
            return 1
            ;;
        /usr|/usr/*|/opt|/opt/*|/etc|/etc/*|/var|/var/*|/lib|/lib/*|/lib64|/lib64/*|/bin|/bin/*|/sbin|/sbin/*|/run|/run/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

blocked_system_path_write() {
    ci_block_path=$1
    ci_block_label=${2:-path}
    ci_blocked "blocker_reason=system_path_write_forbidden label=$ci_block_label path=$ci_block_path"
    return 77
}

assert_not_system_path_for_write() {
    ci_assert_path=$1
    ci_assert_label=${2:-path}
    ci_require_absolute_path "$ci_assert_path" "$ci_assert_label" || return 77
    if ci_path_is_configured_project_path "$ci_assert_path"; then
        return 0
    fi
    if ci_path_is_system_path "$ci_assert_path"; then
        blocked_system_path_write "$ci_assert_path" "$ci_assert_label"
        return 77
    fi
    return 0
}

ci_canonical_path() {
    ci_path=$1
    python3 - "$ci_path" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
    return $?
}

ci_reject_traversal_path() {
    ci_path=$1
    ci_label=${2:-path}
    case "$ci_path" in
        *"/../"*|../*|*/..|..|*"/./"*)
            ci_blocked "$ci_label contains traversal segments: $ci_path"
            return 77
            ;;
    esac
    return 0
}

ci_require_safe_ref() {
    ci_ref=$1
    ci_label=${2:-ref}
    case "$ci_ref" in
        ""|*" "*|*"	"*|*".."*|/*|*/*/*)
            ci_blocked "$ci_label contains unsafe characters: $ci_ref"
            return 77
            ;;
    esac
    if printf '%s' "$ci_ref" | LC_ALL=C grep -Eq '[^A-Za-z0-9._/-]|[$`"'"'"';{}()#&|<>\]'; then
        ci_blocked "$ci_label contains unsupported characters: $ci_ref"
        return 77
    fi
    return 0
}

ci_require_full_git_commit() {
    ci_commit=$1
    ci_label=${2:-git commit}

    case "$ci_commit" in
        ""|*[!0123456789abcdef]*)
            ci_blocked "$ci_label must be a lowercase hexadecimal Git commit: $ci_commit"
            return 77
            ;;
        *)
            if [ "${#ci_commit}" -ne 40 ]; then
                ci_blocked "$ci_label must be a full 40-character Git commit: $ci_commit"
                return 77
            fi
            return 0
            ;;
    esac
}

assert_safe_runtime_path() {
    ci_safe_path=$1
    ci_safe_label=${2:-path}
    ci_state_root="${XDG_STATE_HOME:-$VERIFIED_STATE_ROOT}"
    ci_cache_home="${XDG_CACHE_HOME:-${HOME:-}/.cache}"
    ci_component_cache="${CONNECTOR_COMPONENT_CACHE:-}"
    ci_verified_root="${VERIFIED_RUN_ROOT:-}"

    ci_reject_traversal_path "$ci_safe_path" "$ci_safe_label" || return 77
    ci_safe_path=$(ci_canonical_path "$ci_safe_path")
    assert_not_system_path_for_write "$ci_safe_path" "$ci_safe_label" || return 77
    case "$ci_safe_path" in
        /|/tmp|"${HOME:-__no_home__}")
            ci_blocked "$ci_safe_label is not a safe runtime path: $ci_safe_path"
            return 77
            ;;
        /src|/src/*)
            return 0
            ;;
    esac
    if ci_path_is_configured_project_path "$ci_safe_path"; then
        return 0
    fi
    case "$ci_safe_path" in
        /root|/root/*)
            ci_blocked "$ci_safe_label is under /root and is not a safe runtime path: $ci_safe_path"
            return 77
            ;;
    esac
    if [ -n "${REPO_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$REPO_ROOT"|"$REPO_ROOT"/*)
                ci_blocked "$ci_safe_label is inside a read-only/source checkout: $ci_safe_path"
                return 77
                ;;
        esac
    fi
    if [ -n "${FRAMEWORK_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$FRAMEWORK_ROOT"|"$FRAMEWORK_ROOT"/*)
                ci_blocked "$ci_safe_label is inside a read-only/source checkout: $ci_safe_path"
                return 77
                ;;
        esac
    fi
    if [ -n "${CONNECTOR_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
                ci_blocked "$ci_safe_label is inside a read-only/source checkout: $ci_safe_path"
                return 77
                ;;
        esac
    fi

    case "$ci_safe_path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*|"$TMP_ROOT"|"$TMP_ROOT"/*|"$LOG_ROOT"|"$LOG_ROOT"/*)
            return 0
            ;;
    esac
    if [ -n "$ci_verified_root" ]; then
        case "$ci_safe_path" in
            "$ci_verified_root"|"$ci_verified_root"/*) return 0 ;;
        esac
    fi
    if [ -n "${MRTS_BUILD_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$MRTS_BUILD_ROOT"|"$MRTS_BUILD_ROOT"/*) return 0 ;;
        esac
    fi
    if [ -n "${MRTS_NATIVE_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$MRTS_NATIVE_ROOT"|"$MRTS_NATIVE_ROOT"/*) return 0 ;;
        esac
    fi
    if [ -n "$ci_component_cache" ]; then
        case "$ci_safe_path" in
            "$ci_component_cache"|"$ci_component_cache"/*) return 0 ;;
        esac
    fi
    if [ -n "$ci_state_root" ]; then
        case "$ci_safe_path" in
            "$ci_state_root"|"$ci_state_root"/*) return 0 ;;
        esac
    fi
    if [ -n "$ci_cache_home" ]; then
        case "$ci_safe_path" in
            "$ci_cache_home"|"$ci_cache_home"/*) return 0 ;;
        esac
    fi
    ci_blocked "$ci_safe_label is not under an allowed runtime/cache root: $ci_safe_path"
    return 77
}

safe_remove_runtime_path() {
    ci_remove_target=$1
    ci_remove_owner_root=${2:-}
    ci_remove_label=${3:-runtime path}
    ci_remove_real_target=$(ci_canonical_existing "$ci_remove_target" 2>/dev/null || printf '%s' "$ci_remove_target")

    assert_safe_runtime_path "$ci_remove_real_target" "$ci_remove_label" || return 77
    case "$ci_remove_real_target" in
        /|/src|/tmp|/var|/var/tmp|"${HOME:-__no_home__}"|"$BUILD_ROOT"|"$TMP_ROOT"|"$LOG_ROOT"|"$VERIFIED_RUN_ROOT"|"$CONNECTOR_COMPONENT_CACHE")
            ci_blocked "unsafe remove target for $ci_remove_label: $ci_remove_real_target"
            return 77
            ;;
    esac
    if [ -n "${MRTS_BUILD_ROOT:-}" ] && [ "$ci_remove_real_target" = "$MRTS_BUILD_ROOT" ]; then
        ci_blocked "unsafe remove target for $ci_remove_label: $ci_remove_real_target"
        return 77
    fi
    if [ -n "${MRTS_NATIVE_ROOT:-}" ] && [ "$ci_remove_real_target" = "$MRTS_NATIVE_ROOT" ]; then
        ci_blocked "unsafe remove target for $ci_remove_label: $ci_remove_real_target"
        return 77
    fi
    if [ -n "${CONNECTOR_COMPONENT_CACHE:-}" ] && [ "$ci_remove_real_target" = "$CONNECTOR_COMPONENT_CACHE" ]; then
        ci_blocked "unsafe remove target for $ci_remove_label: $ci_remove_real_target"
        return 77
    fi
    if [ -n "$ci_remove_owner_root" ] && [ "$ci_remove_real_target" = "$ci_remove_owner_root" ]; then
        ci_blocked "unsafe remove target for $ci_remove_label: $ci_remove_real_target"
        return 77
    fi
    if [ -n "$ci_remove_owner_root" ]; then
        assert_not_system_path_for_write "$ci_remove_owner_root" "$ci_remove_label owner root" || return 77
        case "$ci_remove_real_target" in
            "$ci_remove_owner_root"/*) ;;
            *)
                ci_blocked "$ci_remove_label remove target outside owner root: $ci_remove_real_target owner=$ci_remove_owner_root"
                return 77
                ;;
        esac
    fi
    rm -rf "$ci_remove_target"
    return 0
}

cleanup_runtime_workdir() {
    ci_cleanup_target=$1
    ci_cleanup_owner_root=${2:-}
    ci_cleanup_label=${3:-runtime workdir}
    if [ "${KEEP_RUNTIME_ARTIFACTS:-0}" = "1" ]; then
        ci_info "keeping $ci_cleanup_label: $ci_cleanup_target"
        return 0
    fi
    case "$ci_cleanup_target" in
        /tmp/*)
            safe_remove_runtime_path "$ci_cleanup_target" "$ci_cleanup_owner_root" "$ci_cleanup_label"
            return $?
            ;;
        *)
            ci_info "not auto-removing non-/tmp $ci_cleanup_label: $ci_cleanup_target"
            return 0
            ;;
    esac
}

ci_git_value() {
    git_dir=$1
    shift
    if git -C "$git_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$git_dir" "$@" 2>/dev/null || true
    fi
    return 0
}

# Export shared defaults for child scripts invoked after sourcing common.sh.
export DEFAULT_BRANCH FRAMEWORK_ROOT CONNECTOR_ROOT VERIFIED_RUN_ROOT VERIFIED_STATE_ROOT VERIFIED_BUILD_ROOT VERIFIED_SOURCE_ROOT VERIFIED_TMP_ROOT VERIFIED_LOG_ROOT CACHE_ROOT VERIFIED_COMPONENT_CACHE
export SOURCE_ROOT BUILD_ROOT TMP_ROOT LOG_ROOT CONNECTOR_COMPONENT_CACHE DEFAULT_PYTHON HAPROXY_BIN_WAS_SET
export CRS_REPO_URL CRS_GIT_REF MODSECURITY_REPO_URL MODSECURITY_GIT_REF MODSECURITY_V3_GIT_URL MODSECURITY_V3_GIT_REF
export HTTPD_VERSION HTTPD_SOURCE_URL HTTPD_SHA256 HTTPD_SHA256_URL APR_VERSION APR_SOURCE_URL APR_SHA256 APR_SHA256_URL APR_UTIL_VERSION APR_UTIL_SOURCE_URL APR_UTIL_SHA256 APR_UTIL_SHA256_URL PCRE2_VERSION PCRE2_SOURCE_URL PCRE2_SHA256 PCRE2_SHA256_URL
export NGINX_SOURCE_MODE NGINX_SOURCE_REPO_URL NGINX_GITHUB_REPO NGINX_RELEASE_TAG NGINX_SOURCE_GIT_REF NGINX_SHA256 HAPROXY_VERSION HAPROXY_SOURCE_URL HAPROXY_SHA256_URL HAPROXY_SHA256
