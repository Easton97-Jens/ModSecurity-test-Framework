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

# Keep the inherited process environment as an inert byte-for-byte snapshot
# before any canonical assignment below can overwrite an exported shell
# variable.  Use only fixed system paths: a caller-defined `env` shell
# function or PATH entry must not execute merely because common.sh is sourced.
# The snapshot is consulted only by ci_require_canonical_active_upstream_pins;
# it is never evaluated as shell code.  This provides one generic guard for
# every active pin instead of a caller-controlled value silently disappearing
# when this file is sourced.
if [ -x /usr/bin/env ]; then
    CI_INHERITED_UPSTREAM_ENV=$(/usr/bin/env)
    CI_INHERITED_UPSTREAM_ENV_STATUS=0
elif [ -x /bin/env ]; then
    CI_INHERITED_UPSTREAM_ENV=$(/bin/env)
    CI_INHERITED_UPSTREAM_ENV_STATUS=0
else
    CI_INHERITED_UPSTREAM_ENV=
    CI_INHERITED_UPSTREAM_ENV_STATUS=77
fi

# Canonical active upstream pins.  This file is the only manually maintained
# authority for active versions, release identities, assets, URLs, platforms,
# commits, and digests.  Consumers may derive, generate, or validate values
# from these assignments, but must not introduce another active authority.
#
# These are passive local values only: checks, downloads, installs, and
# directory creation happen outside common.sh.  In particular, upstream tuple
# variables deliberately do not use ${VAR:-...}; an exported environment value
# must never replace the reviewed source identity.
# Do not pass GNU Make's pre-parser control variables into child Make calls
# from shell entrypoints that source this library.  The trusted top-level
# wrapper clears these before Make starts; this covers the remaining shell
# boundary without changing filesystem state or normal command arguments.
unset MAKE MAKEFLAGS GNUMAKEFLAGS MAKEFILES MAKEOVERRIDES MFLAGS MAKELEVEL

ENVOY_VERSION="1.39.0"
ENVOY_SOURCE_URL="https://github.com/envoyproxy/envoy/releases"
ENVOY_INSTALL_DOCS_URL="https://www.envoyproxy.io/docs/envoy/latest/start/install"
ENVOY_ARTIFACT_PLATFORM="linux-x86_64"
ENVOY_ASSET_NAME="envoy-$ENVOY_VERSION-$ENVOY_ARTIFACT_PLATFORM"
ENVOY_DOWNLOAD_URL="$ENVOY_SOURCE_URL/download/v$ENVOY_VERSION/$ENVOY_ASSET_NAME"
ENVOY_SHA256="4409dadc87931d8f8676314cbd83071cb65125fb4feac3f6335800580dfa9218"
ENVOY_SHA256_URL="$ENVOY_SOURCE_URL/download/v$ENVOY_VERSION/checksums.txt.asc"
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

# Traefik is one reviewed release-archive tuple.  The selected artifact is
# exactly the upstream Linux amd64 tarball; its SHA-256 must never be reused
# for a binary, OCI image, manifest index, or another platform.  Keep these
# assignments at column zero so the common-version resolver can update the
# version and digest together without evaluating shell code.
ci_traefik_set_canonical_tuple() {
TRAEFIK_VERSION="3.7.10"
TRAEFIK_SOURCE_URL="https://github.com/traefik/traefik/releases"
TRAEFIK_INSTALL_DOCS_URL="https://doc.traefik.io/traefik/getting-started/install-traefik/"
TRAEFIK_ARTIFACT_PLATFORM="linux_amd64"
TRAEFIK_ARCHIVE_NAME="traefik_v${TRAEFIK_VERSION}_${TRAEFIK_ARTIFACT_PLATFORM}.tar.gz"
TRAEFIK_DOWNLOAD_URL="$TRAEFIK_SOURCE_URL/download/v$TRAEFIK_VERSION/$TRAEFIK_ARCHIVE_NAME"
TRAEFIK_SHA256="01811bb12d44f17280550f425f5e3128d6c325f2665c09e67a651ca535f490ce"
TRAEFIK_SHA256_URL="$TRAEFIK_SOURCE_URL/download/v$TRAEFIK_VERSION/traefik_v${TRAEFIK_VERSION}_checksums.txt"
}

# Capture the exact inherited state before overwriting it with the reviewed
# tuple.  The snapshots distinguish an unset field from an explicit empty
# field, are reset on every source, and are intentionally not exported.
unset CI_TRAEFIK_VERSION_WAS_SET CI_TRAEFIK_VERSION_BEFORE_SOURCE
unset CI_TRAEFIK_SOURCE_URL_WAS_SET CI_TRAEFIK_SOURCE_URL_BEFORE_SOURCE
unset CI_TRAEFIK_DOWNLOAD_URL_WAS_SET CI_TRAEFIK_DOWNLOAD_URL_BEFORE_SOURCE
unset CI_TRAEFIK_SHA256_WAS_SET CI_TRAEFIK_SHA256_BEFORE_SOURCE
unset CI_TRAEFIK_SHA256_URL_WAS_SET CI_TRAEFIK_SHA256_URL_BEFORE_SOURCE
unset CI_TRAEFIK_ARTIFACT_PLATFORM_WAS_SET CI_TRAEFIK_ARTIFACT_PLATFORM_BEFORE_SOURCE
unset CI_TRAEFIK_ARCHIVE_NAME_WAS_SET CI_TRAEFIK_ARCHIVE_NAME_BEFORE_SOURCE
unset CI_TRAEFIK_BIN_WAS_SET CI_TRAEFIK_BIN_BEFORE_SOURCE
if [ "${TRAEFIK_VERSION+x}" = x ]; then
    CI_TRAEFIK_VERSION_WAS_SET=1
    CI_TRAEFIK_VERSION_BEFORE_SOURCE=$TRAEFIK_VERSION
else
    CI_TRAEFIK_VERSION_WAS_SET=0
    CI_TRAEFIK_VERSION_BEFORE_SOURCE=
fi
if [ "${TRAEFIK_SOURCE_URL+x}" = x ]; then
    CI_TRAEFIK_SOURCE_URL_WAS_SET=1
    CI_TRAEFIK_SOURCE_URL_BEFORE_SOURCE=$TRAEFIK_SOURCE_URL
else
    CI_TRAEFIK_SOURCE_URL_WAS_SET=0
    CI_TRAEFIK_SOURCE_URL_BEFORE_SOURCE=
fi
if [ "${TRAEFIK_DOWNLOAD_URL+x}" = x ]; then
    CI_TRAEFIK_DOWNLOAD_URL_WAS_SET=1
    CI_TRAEFIK_DOWNLOAD_URL_BEFORE_SOURCE=$TRAEFIK_DOWNLOAD_URL
else
    CI_TRAEFIK_DOWNLOAD_URL_WAS_SET=0
    CI_TRAEFIK_DOWNLOAD_URL_BEFORE_SOURCE=
fi
if [ "${TRAEFIK_SHA256+x}" = x ]; then
    CI_TRAEFIK_SHA256_WAS_SET=1
    CI_TRAEFIK_SHA256_BEFORE_SOURCE=$TRAEFIK_SHA256
else
    CI_TRAEFIK_SHA256_WAS_SET=0
    CI_TRAEFIK_SHA256_BEFORE_SOURCE=
fi
if [ "${TRAEFIK_SHA256_URL+x}" = x ]; then
    CI_TRAEFIK_SHA256_URL_WAS_SET=1
    CI_TRAEFIK_SHA256_URL_BEFORE_SOURCE=$TRAEFIK_SHA256_URL
else
    CI_TRAEFIK_SHA256_URL_WAS_SET=0
    CI_TRAEFIK_SHA256_URL_BEFORE_SOURCE=
fi
if [ "${TRAEFIK_ARTIFACT_PLATFORM+x}" = x ]; then
    CI_TRAEFIK_ARTIFACT_PLATFORM_WAS_SET=1
    CI_TRAEFIK_ARTIFACT_PLATFORM_BEFORE_SOURCE=$TRAEFIK_ARTIFACT_PLATFORM
else
    CI_TRAEFIK_ARTIFACT_PLATFORM_WAS_SET=0
    CI_TRAEFIK_ARTIFACT_PLATFORM_BEFORE_SOURCE=
fi
if [ "${TRAEFIK_ARCHIVE_NAME+x}" = x ]; then
    CI_TRAEFIK_ARCHIVE_NAME_WAS_SET=1
    CI_TRAEFIK_ARCHIVE_NAME_BEFORE_SOURCE=$TRAEFIK_ARCHIVE_NAME
else
    CI_TRAEFIK_ARCHIVE_NAME_WAS_SET=0
    CI_TRAEFIK_ARCHIVE_NAME_BEFORE_SOURCE=
fi
if [ "${TRAEFIK_BIN+x}" = x ]; then
    CI_TRAEFIK_BIN_WAS_SET=1
    CI_TRAEFIK_BIN_BEFORE_SOURCE=$TRAEFIK_BIN
else
    CI_TRAEFIK_BIN_WAS_SET=0
    CI_TRAEFIK_BIN_BEFORE_SOURCE=
fi
ci_traefik_set_canonical_tuple
TRAEFIK_COMPONENT_ROOT="${TRAEFIK_COMPONENT_ROOT:-$CONNECTOR_COMPONENT_CACHE/traefik}"
TRAEFIK_RUNTIME_ROOT="${TRAEFIK_RUNTIME_ROOT:-$VERIFIED_RUN_ROOT/traefik-smoke}"
TRAEFIK_CONFIG_ROOT="${TRAEFIK_CONFIG_ROOT:-$TRAEFIK_RUNTIME_ROOT/config}"
TRAEFIK_LOG_ROOT="${TRAEFIK_LOG_ROOT:-$VERIFIED_LOG_ROOT/traefik-smoke}"
TRAEFIK_RESULT_ROOT="${TRAEFIK_RESULT_ROOT:-$VERIFIED_RUN_ROOT/traefik-smoke}"
TRAEFIK_ARCHIVE="$TRAEFIK_COMPONENT_ROOT/downloads/$TRAEFIK_ARCHIVE_NAME"
TRAEFIK_SOURCE_ROOT="${TRAEFIK_SOURCE_ROOT:-$TRAEFIK_COMPONENT_ROOT/src/traefik-$TRAEFIK_VERSION}"
TRAEFIK_BUILD_ROOT="${TRAEFIK_BUILD_ROOT:-$BUILD_ROOT/traefik-connector}"
TRAEFIK_BIN="$TRAEFIK_BUILD_ROOT/bin/traefik"
TRAEFIK_SMOKE_PORT="${TRAEFIK_SMOKE_PORT:-18180}"
TRAEFIK_UPSTREAM_PORT="${TRAEFIK_UPSTREAM_PORT:-18181}"
TRAEFIK_AUTHZ_PORT="${TRAEFIK_AUTHZ_PORT:-18182}"
TRAEFIK_INTEGRATION_MODE="${TRAEFIK_INTEGRATION_MODE:-forwardAuth}"

LIGHTTPD_SERIES="1.4"
LIGHTTPD_RELEASE_ROOT_URL="https://download.lighttpd.net/lighttpd"
LIGHTTPD_SERIES_BASE_URL="$LIGHTTPD_RELEASE_ROOT_URL/releases-$LIGHTTPD_SERIES.x"
LIGHTTPD_VERSION="1.4.85"
LIGHTTPD_SOURCE_URL="$LIGHTTPD_SERIES_BASE_URL/"
LIGHTTPD_RELEASE_INDEX_URL="$LIGHTTPD_SOURCE_URL"
LIGHTTPD_LATEST_URL="${LIGHTTPD_SERIES_BASE_URL}/latest.txt"
LIGHTTPD_ARCHIVE_NAME="lighttpd-$LIGHTTPD_VERSION.tar.xz"
LIGHTTPD_DOWNLOAD_URL="$LIGHTTPD_SOURCE_URL$LIGHTTPD_ARCHIVE_NAME"
LIGHTTPD_SHA256="18de51b393bac4a6827879e1a7ff377c169e414bae92cd245091d80fc2601d13"
LIGHTTPD_SHA256_URL="${LIGHTTPD_SOURCE_URL}lighttpd-$LIGHTTPD_VERSION.sha256sum"
LIGHTTPD_COMPONENT_ROOT="${LIGHTTPD_COMPONENT_ROOT:-$CONNECTOR_COMPONENT_CACHE/lighttpd}"
LIGHTTPD_RUNTIME_ROOT="${LIGHTTPD_RUNTIME_ROOT:-$VERIFIED_RUN_ROOT/lighttpd-smoke}"
LIGHTTPD_CONFIG_ROOT="${LIGHTTPD_CONFIG_ROOT:-$LIGHTTPD_RUNTIME_ROOT/config}"
LIGHTTPD_LOG_ROOT="${LIGHTTPD_LOG_ROOT:-$VERIFIED_LOG_ROOT/lighttpd-smoke}"
LIGHTTPD_RESULT_ROOT="${LIGHTTPD_RESULT_ROOT:-$VERIFIED_RUN_ROOT/lighttpd-smoke}"
LIGHTTPD_CONNECTOR_BUILD_ROOT="${LIGHTTPD_CONNECTOR_BUILD_ROOT:-$BUILD_ROOT/lighttpd-connector}"
LIGHTTPD_BIN="${LIGHTTPD_BIN:-$LIGHTTPD_CONNECTOR_BUILD_ROOT/bin/lighttpd}"
LIGHTTPD_SOURCE_DIR="${LIGHTTPD_SOURCE_DIR:-$LIGHTTPD_CONNECTOR_BUILD_ROOT/src/lighttpd-$LIGHTTPD_VERSION}"
LIGHTTPD_BUILD_ROOT="${LIGHTTPD_BUILD_ROOT:-$LIGHTTPD_CONNECTOR_BUILD_ROOT/build/lighttpd-$LIGHTTPD_VERSION}"
LIGHTTPD_INCLUDE_DIR="${LIGHTTPD_INCLUDE_DIR:-$LIGHTTPD_SOURCE_DIR/src}"
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
# the environment. fetch-crs.sh fetches this exact reviewed release tag only
# to prove that its peeled object is the immutable approved commit; it never
# accepts the tag as a caller-selectable source identity.
CRS_APPROVED_REPO_URL="https://github.com/coreruleset/coreruleset.git"
CRS_APPROVED_COMMIT="55b09f5acfd16413e7b31041100711ceb7adc89c"
CRS_RELEASE_TAG="v4.28.0"
CRS_REPO_URL="$CRS_APPROVED_REPO_URL"
CRS_GIT_REF="$CRS_RELEASE_TAG"

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

# ModSecurity v3 provenance is a fixed reviewed identity.  The legacy
# MODSECURITY_* aliases remain available as compatibility metadata, but the
# V3 provisioning and build paths verify that they match this exact identity
# before any Git operation or source consumption.
MODSECURITY_V3_APPROVED_REPO_URL="https://github.com/owasp-modsecurity/ModSecurity.git"
MODSECURITY_V3_APPROVED_COMMIT="0fb4aff98b4980cf6426697d5605c424e3d5bb60"
MODSECURITY_V3_RELEASE_TAG="v3.0.15"
MODSECURITY_REPO_URL="$MODSECURITY_V3_APPROVED_REPO_URL"
MODSECURITY_GIT_REF="$MODSECURITY_V3_RELEASE_TAG"
MODSECURITY_V3_GIT_URL="$MODSECURITY_V3_APPROVED_REPO_URL"
MODSECURITY_V3_GIT_REF="$MODSECURITY_V3_RELEASE_TAG"

ALLOW_EXTERNAL_CONNECTOR_REPOS="${ALLOW_EXTERNAL_CONNECTOR_REPOS:-0}"
# Optional: external connector repositories are empty by default because this repository
# carries local connector sources unless ALLOW_EXTERNAL_CONNECTOR_REPOS=1.
MODSECURITY_APACHE_REPO_URL="${MODSECURITY_APACHE_REPO_URL:-${MODSECURITY_APACHE_GIT_URL:-}}"
MODSECURITY_APACHE_GIT_URL="${MODSECURITY_APACHE_GIT_URL:-$MODSECURITY_APACHE_REPO_URL}"
MODSECURITY_APACHE_GIT_REF="${MODSECURITY_APACHE_GIT_REF:-$DEFAULT_BRANCH}"

MODSECURITY_NGINX_REPO_URL="${MODSECURITY_NGINX_REPO_URL:-${MODSECURITY_NGINX_GIT_URL:-}}"
MODSECURITY_NGINX_GIT_URL="${MODSECURITY_NGINX_GIT_URL:-$MODSECURITY_NGINX_REPO_URL}"
MODSECURITY_NGINX_GIT_REF="${MODSECURITY_NGINX_GIT_REF:-$DEFAULT_BRANCH}"

HTTPD_VERSION="2.4.68"
HTTPD_ARCHIVE_NAME="httpd-$HTTPD_VERSION.tar.bz2"
HTTPD_SOURCE_URL="https://downloads.apache.org/httpd/$HTTPD_ARCHIVE_NAME"
HTTPD_SHA256="68c74d4df38c26bed4dfbdb8f3baf1eb532f3872357becc1bba5d136f6b63c06"
HTTPD_SHA256_URL="$HTTPD_SOURCE_URL.sha256"
APR_VERSION="1.7.6"
APR_ARCHIVE_NAME="apr-$APR_VERSION.tar.bz2"
APR_SOURCE_URL="https://downloads.apache.org/apr/$APR_ARCHIVE_NAME"
APR_SHA256="49030d92d2575da735791b496dc322f3ce5cff9494779ba8cc28c7f46c5deb32"
APR_SHA256_URL="$APR_SOURCE_URL.sha256"
# APR-util is one atomic, reviewed provider tuple.  The version is declared
# exactly once; both provider URLs are derived from it.  Keep the assignments
# at column zero so the common-version resolver can update the version and
# digest atomically without evaluating shell code.
ci_apr_util_set_canonical_tuple() {
APR_UTIL_VERSION="1.6.5"
APR_UTIL_ARCHIVE_NAME="apr-util-$APR_UTIL_VERSION.tar.bz2"
APR_UTIL_SOURCE_URL="https://downloads.apache.org/apr/$APR_UTIL_ARCHIVE_NAME"
APR_UTIL_SHA256="96de1dd6f6a0476d2d2e7964926d8c1ddc3bb0e210e1b1812d3ba5a454a392e2"
APR_UTIL_SHA256_URL="$APR_UTIL_SOURCE_URL.sha256"
}

# Capture the exact inherited state before overwriting it with the reviewed
# tuple.  The snapshots distinguish an unset field from an explicit empty
# field, are reset on every source, and are intentionally not exported.
unset CI_APR_UTIL_VERSION_WAS_SET CI_APR_UTIL_VERSION_BEFORE_SOURCE
unset CI_APR_UTIL_SOURCE_URL_WAS_SET CI_APR_UTIL_SOURCE_URL_BEFORE_SOURCE
unset CI_APR_UTIL_SHA256_WAS_SET CI_APR_UTIL_SHA256_BEFORE_SOURCE
unset CI_APR_UTIL_SHA256_URL_WAS_SET CI_APR_UTIL_SHA256_URL_BEFORE_SOURCE
if [ "${APR_UTIL_VERSION+x}" = x ]; then
    CI_APR_UTIL_VERSION_WAS_SET=1
    CI_APR_UTIL_VERSION_BEFORE_SOURCE=$APR_UTIL_VERSION
else
    CI_APR_UTIL_VERSION_WAS_SET=0
    CI_APR_UTIL_VERSION_BEFORE_SOURCE=
fi
if [ "${APR_UTIL_SOURCE_URL+x}" = x ]; then
    CI_APR_UTIL_SOURCE_URL_WAS_SET=1
    CI_APR_UTIL_SOURCE_URL_BEFORE_SOURCE=$APR_UTIL_SOURCE_URL
else
    CI_APR_UTIL_SOURCE_URL_WAS_SET=0
    CI_APR_UTIL_SOURCE_URL_BEFORE_SOURCE=
fi
if [ "${APR_UTIL_SHA256+x}" = x ]; then
    CI_APR_UTIL_SHA256_WAS_SET=1
    CI_APR_UTIL_SHA256_BEFORE_SOURCE=$APR_UTIL_SHA256
else
    CI_APR_UTIL_SHA256_WAS_SET=0
    CI_APR_UTIL_SHA256_BEFORE_SOURCE=
fi
if [ "${APR_UTIL_SHA256_URL+x}" = x ]; then
    CI_APR_UTIL_SHA256_URL_WAS_SET=1
    CI_APR_UTIL_SHA256_URL_BEFORE_SOURCE=$APR_UTIL_SHA256_URL
else
    CI_APR_UTIL_SHA256_URL_WAS_SET=0
    CI_APR_UTIL_SHA256_URL_BEFORE_SOURCE=
fi
ci_apr_util_set_canonical_tuple
PCRE2_VERSION="10.47"
PCRE2_ARCHIVE_NAME="pcre2-$PCRE2_VERSION.tar.bz2"
PCRE2_SOURCE_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_VERSION/$PCRE2_ARCHIVE_NAME"
# The literal pin is required before the PCRE2 archive can be extracted.  Use
# the no-colon expansion so an explicitly empty caller override fails closed.
PCRE2_SHA256="47fe8c99461250d42f89e6e8fdaeba9da057855d06eb7fc08d9ca03fd08d7bc7"
# PCRE2 release assets do not publish a stable per-asset SHA256 URL.  This
# metadata variable is retained for version tooling; it is not an extraction
# verification fallback.
PCRE2_SHA256_URL=""

NGINX_SOURCE_MODE="github-release"
NGINX_SOURCE_REPO_URL="https://github.com/nginx/nginx"
NGINX_GITHUB_REPO="$NGINX_SOURCE_REPO_URL"
NGINX_RELEASE_TAG="release-1.31.3"
NGINX_SOURCE_GIT_REF="$NGINX_RELEASE_TAG"
# NGINX source provenance is an atomic binding: the official GitHub release
# tag, its exact release asset, and the digest GitHub publishes for that asset
# are reviewed together.  Do not update one member of this tuple alone.
NGINX_RELEASE_ASSET_NAME="nginx-${NGINX_RELEASE_TAG#release-}.tar.gz"
NGINX_DOWNLOAD_URL="$NGINX_SOURCE_REPO_URL/releases/download/$NGINX_RELEASE_TAG/$NGINX_RELEASE_ASSET_NAME"
if [ "${NGINX_SHA256+x}" = x ]; then
    NGINX_SHA256_WAS_SET=1
else
    NGINX_SHA256_WAS_SET=0
fi
NGINX_SHA256_REQUESTED="${NGINX_SHA256-}"
NGINX_SHA256="a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525"

# Managed NGINX protocol builds are deliberately explicit.  The default keeps
# the established clear-text HTTP/1.1 smoke path unchanged; H2/H3 are opted in
# by selecting a profile at build time.  The H3 profile uses a pinned OpenSSL
# source tree rather than silently relying on whichever system TLS library is
# installed.  The source is only fetched/extracted by prepare-nginx-build.sh
# when that profile is selected.
NGINX_PROTOCOL_PROFILE="${NGINX_PROTOCOL_PROFILE:-h1}"
NGINX_QUIC_TLS_LIBRARY="${NGINX_QUIC_TLS_LIBRARY:-openssl}"
NGINX_QUIC_TLS_VERSION="4.0.1"
NGINX_QUIC_TLS_ARCHIVE_NAME="openssl-$NGINX_QUIC_TLS_VERSION.tar.gz"
NGINX_QUIC_TLS_SOURCE_URL="https://github.com/openssl/openssl/releases/download/openssl-$NGINX_QUIC_TLS_VERSION/$NGINX_QUIC_TLS_ARCHIVE_NAME"
NGINX_QUIC_TLS_SOURCE_SHA256="2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"
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

HAPROXY_SERIES="3.2"
HAPROXY_RELEASE_ROOT_URL="https://www.haproxy.org/download"
HAPROXY_SERIES_BASE_URL="$HAPROXY_RELEASE_ROOT_URL/$HAPROXY_SERIES/src"
HAPROXY_VERSION="3.2.22"
HAPROXY_ARCHIVE_NAME="haproxy-$HAPROXY_VERSION.tar.gz"
HAPROXY_SOURCE_URL="$HAPROXY_SERIES_BASE_URL/$HAPROXY_ARCHIVE_NAME"
HAPROXY_SHA256_URL="$HAPROXY_SOURCE_URL.sha256"
HAPROXY_SHA256="afca3a26d573df53d0e1fc475dcd743ec5875e038e1476c80e871d70228ca2da"
HAPROXY_HTX_SERIES="3.2"
HAPROXY_HTX_SERIES_BASE_URL="$HAPROXY_RELEASE_ROOT_URL/$HAPROXY_HTX_SERIES/src"
HAPROXY_HTX_VERSION="3.2.21"
HAPROXY_HTX_ARCHIVE_NAME="haproxy-$HAPROXY_HTX_VERSION.tar.gz"
HAPROXY_HTX_SOURCE_URL="$HAPROXY_HTX_SERIES_BASE_URL/$HAPROXY_HTX_ARCHIVE_NAME"
HAPROXY_HTX_SHA256="0cb8818a26c5f888e0cb1c40f1b3acb9fb952527d1733f769ce688fedd680339"
HAPROXY_SOURCE_ROOT="${HAPROXY_SOURCE_ROOT:-$SOURCE_ROOT/haproxy}"
HAPROXY_DOWNLOAD_DIR="${HAPROXY_DOWNLOAD_DIR:-$HAPROXY_SOURCE_ROOT/downloads}"
HAPROXY_SOURCE_DIR="${HAPROXY_SOURCE_DIR:-$HAPROXY_SOURCE_ROOT/haproxy-$HAPROXY_VERSION}"
HAPROXY_RUNTIME_BUILD_DIR="${HAPROXY_RUNTIME_BUILD_DIR:-$BUILD_ROOT/haproxy-runtime-build}"
HAPROXY_RUNTIME_BUILD_WORKTREE="${HAPROXY_RUNTIME_BUILD_WORKTREE:-$HAPROXY_RUNTIME_BUILD_DIR/worktree}"
HAPROXY_RUNTIME_DIR="${HAPROXY_RUNTIME_DIR:-$BUILD_ROOT/haproxy-runtime/haproxy}"
HAPROXY_BIN="${HAPROXY_BIN:-$HAPROXY_RUNTIME_DIR/sbin/haproxy}"

GO_FTW_SOURCE_URL="https://github.com/coreruleset/go-ftw"
GO_FTW_RELEASE_TAG="v2.2.0"
GO_FTW_GIT_REF="$GO_FTW_RELEASE_TAG"
GO_FTW_PROMPT_EXPECTED_LATEST="$GO_FTW_RELEASE_TAG"
GO_FTW_APPROVED_COMMIT="eb6d056074bea4156878e0eb852212a6908b87a9"
GO_FTW_BIN="${GO_FTW_BIN:-go-ftw}"

ALBEDO_SOURCE_URL="https://github.com/coreruleset/albedo"
ALBEDO_RELEASE_TAG="v0.3.0"
ALBEDO_GIT_REF="$ALBEDO_RELEASE_TAG"
ALBEDO_PROMPT_EXPECTED_LATEST="$ALBEDO_RELEASE_TAG"
ALBEDO_APPROVED_COMMIT="3f7d0238b32d1f98059f5c70e0ffcafad514952c"
ALBEDO_BIN="${ALBEDO_BIN:-albedo}"

EXPAT_SOURCE_URL="https://github.com/libexpat/libexpat"
# Expat is maintenance metadata only; no active Framework provisioning path
# consumes it.  Keep the existing branch marker immutable to this task rather
# than fabricating a new upstream commit without a reviewed dependency update.
EXPAT_GIT_REF="master"
EXPAT_GIT_URL="$EXPAT_SOURCE_URL"
EXPAT_PROMPT_EXPECTED_LATEST="$EXPAT_GIT_REF"

# CI workflow, native-tool, and interpreter provenance is also canonical here.
# YAML and documentation cannot source shell at runtime, so the checked-in
# representations are deterministic generated views validated by the sync
# tools.  Repository identifiers are part of the upstream identity; keep
# release and asset URLs derived from them rather than duplicating URLs in
# workflow or lock files.
CI_CANONICAL_PYTHON_VERSION="3.14.7"
CI_CANONICAL_PYYAML_VERSION="6.0.3"
CI_CANONICAL_PYYAML_SHA256="c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5"
CI_CANONICAL_PYYAML_ARTIFACT="pyyaml-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
CI_CANONICAL_PYYAML_PLATFORM="manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64"
CI_CANONICAL_NODE_VERSION="24.18.0"
# The pull-request OSV workflow has one compatibility exception for the
# historical base revision that predates the current Python line.  Keep this
# exact revision/version tuple canonical here; the workflow synchronizer emits
# the two env fields as a generated view and never sources this file at run
# time.
CI_OSV_LEGACY_BASE_SHA="f73f8842f45318e2df8aff1d31855eeb7c20a22f"
CI_OSV_LEGACY_BASE_VERSION="3.13.14"

CI_ACTION_CHECKOUT_REPOSITORY="actions/checkout"
CI_ACTION_CHECKOUT_VERSION="v7.0.1"
CI_ACTION_CHECKOUT_COMMIT="3d3c42e5aac5ba805825da76410c181273ba90b1"
CI_ACTION_SETUP_PYTHON_REPOSITORY="actions/setup-python"
CI_ACTION_SETUP_PYTHON_VERSION="v7.0.0"
CI_ACTION_SETUP_PYTHON_COMMIT="5fda3b95a4ea91299a34e894583c3862153e4b97"
CI_ACTION_SETUP_NODE_REPOSITORY="actions/setup-node"
CI_ACTION_SETUP_NODE_VERSION="v7.0.0"
CI_ACTION_SETUP_NODE_COMMIT="820762786026740c76f36085b0efc47a31fe5020"
CI_ACTION_UPLOAD_ARTIFACT_REPOSITORY="actions/upload-artifact"
CI_ACTION_UPLOAD_ARTIFACT_VERSION="v7.0.1"
CI_ACTION_UPLOAD_ARTIFACT_COMMIT="043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
CI_ACTION_DOWNLOAD_ARTIFACT_REPOSITORY="actions/download-artifact"
CI_ACTION_DOWNLOAD_ARTIFACT_VERSION="v8.0.1"
CI_ACTION_DOWNLOAD_ARTIFACT_COMMIT="3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
CI_ACTION_GITHUB_SCRIPT_REPOSITORY="actions/github-script"
CI_ACTION_GITHUB_SCRIPT_VERSION="v9.0.0"
CI_ACTION_GITHUB_SCRIPT_COMMIT="3a2844b7e9c422d3c10d287c895573f7108da1b3"
CI_ACTION_CREATE_GITHUB_APP_TOKEN_REPOSITORY="actions/create-github-app-token"
CI_ACTION_CREATE_GITHUB_APP_TOKEN_VERSION="v3.2.0"
CI_ACTION_CREATE_GITHUB_APP_TOKEN_COMMIT="bcd2ba49218906704ab6c1aa796996da409d3eb1"
CI_ACTION_CREATE_PULL_REQUEST_REPOSITORY="peter-evans/create-pull-request"
CI_ACTION_CREATE_PULL_REQUEST_VERSION="v8.1.1"
CI_ACTION_CREATE_PULL_REQUEST_COMMIT="5f6978faf089d4d20b00c7766989d076bb2fc7f1"
CI_ACTION_CODEQL_REPOSITORY="github/codeql-action"
CI_ACTION_CODEQL_VERSION="v4.37.6"
CI_ACTION_CODEQL_COMMIT="5595ccaf912efad79be6eef63a5619ff05969be3"
CI_ACTION_DEPENDENCY_REVIEW_REPOSITORY="actions/dependency-review-action"
CI_ACTION_DEPENDENCY_REVIEW_VERSION="v5.0.0"
CI_ACTION_DEPENDENCY_REVIEW_COMMIT="a1d282b36b6f3519aa1f3fc636f609c47dddb294"

CI_SECURITY_TOOL_SCORECARD_REPOSITORY="ossf/scorecard"
CI_SECURITY_TOOL_SCORECARD_VERSION="v5.5.0"
CI_SECURITY_TOOL_SCORECARD_COMMIT="c395761df6afe1a69e476bc60a013a94bcbc153f"
CI_SECURITY_TOOL_SCORECARD_ASSET_NAME="scorecard_${CI_SECURITY_TOOL_SCORECARD_VERSION#v}_linux_amd64.tar.gz"
CI_SECURITY_TOOL_SCORECARD_SHA256="83b90a05c1540ef1390db1cd5711e5fd04be9c1d8537fb84d39d02092d6a8dff"
CI_SECURITY_TOOL_OSV_SCANNER_REPOSITORY="google/osv-scanner"
CI_SECURITY_TOOL_OSV_SCANNER_VERSION="v2.5.0"
CI_SECURITY_TOOL_OSV_SCANNER_COMMIT="a258868211a57052da6bd323f758b8388dee02bb"
CI_SECURITY_TOOL_OSV_SCANNER_ASSET_NAME="osv-scanner_linux_amd64"
CI_SECURITY_TOOL_OSV_SCANNER_SHA256="edcfc41d257db36148f065055655fe3fcfc434b0b423ea67468a84c207524e0c"
CI_SECURITY_TOOL_ACTIONLINT_REPOSITORY="rhysd/actionlint"
CI_SECURITY_TOOL_ACTIONLINT_VERSION="v1.7.12"
CI_SECURITY_TOOL_ACTIONLINT_COMMIT="914e7df21a07ef503a81201c76d2b11c789d3fca"
CI_SECURITY_TOOL_ACTIONLINT_ASSET_NAME="actionlint_${CI_SECURITY_TOOL_ACTIONLINT_VERSION#v}_linux_amd64.tar.gz"
CI_SECURITY_TOOL_ACTIONLINT_SHA256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
CI_SECURITY_TOOL_SHELLCHECK_REPOSITORY="koalaman/shellcheck"
CI_SECURITY_TOOL_SHELLCHECK_VERSION="v0.11.0"
CI_SECURITY_TOOL_SHELLCHECK_COMMIT="aac0823e6b58f8a499e856e93738082691cbf212"
CI_SECURITY_TOOL_SHELLCHECK_ASSET_NAME="shellcheck-${CI_SECURITY_TOOL_SHELLCHECK_VERSION}.linux.x86_64.tar.gz"
CI_SECURITY_TOOL_SHELLCHECK_SHA256="b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6"
CI_SECURITY_TOOL_ZIZMOR_REPOSITORY="zizmorcore/zizmor"
CI_SECURITY_TOOL_ZIZMOR_VERSION="v1.29.0"
CI_SECURITY_TOOL_ZIZMOR_COMMIT="3c116961091b50bd1a08ffefe916469d4d90093c"
CI_SECURITY_TOOL_ZIZMOR_ASSET_NAME="zizmor-x86_64-unknown-linux-gnu.tar.gz"
CI_SECURITY_TOOL_ZIZMOR_SHA256="dd96df044a6e8538d5f423790f453bdd03d49e5b2bcc38214acc41a2f1297839"
CI_SECURITY_TOOL_GITLEAKS_REPOSITORY="gitleaks/gitleaks"
CI_SECURITY_TOOL_GITLEAKS_VERSION="v8.30.1"
CI_SECURITY_TOOL_GITLEAKS_COMMIT="83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
CI_SECURITY_TOOL_GITLEAKS_ASSET_NAME="gitleaks_${CI_SECURITY_TOOL_GITLEAKS_VERSION#v}_linux_x64.tar.gz"
CI_SECURITY_TOOL_GITLEAKS_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
CI_SECURITY_TOOL_RUFF_REPOSITORY="astral-sh/ruff"
CI_SECURITY_TOOL_RUFF_VERSION="0.16.2"
CI_SECURITY_TOOL_RUFF_COMMIT="5b48a040974781ba90b47c8df628f8fd9b6c95dd"
CI_SECURITY_TOOL_RUFF_ASSET_NAME="ruff-x86_64-unknown-linux-gnu.tar.gz"
CI_SECURITY_TOOL_RUFF_SHA256="3d2c355e641ceb5b608a158c603768fcc908c5009c56c6e78da7487da033b92a"
CI_SECURITY_TOOL_PYRIGHT_REPOSITORY="microsoft/pyright"
CI_SECURITY_TOOL_PYRIGHT_VERSION="1.1.411"
CI_SECURITY_TOOL_PYRIGHT_COMMIT="9a9205fc32a2685767f38f348f5d9232701d4b0b"
CI_SECURITY_TOOL_PYRIGHT_ASSET_NAME="pyright.tgz"
CI_SECURITY_TOOL_PYRIGHT_SHA256="bd5c488fc20fa237a944279bf32cae2f986cf10d5d5d9e8705819859daeb2f4a"

# Retain the values established by this source operation as derived runtime
# expectations.  They contain no second manually maintained pin and allow a
# consumer to reject a post-source mutation before it reaches a download,
# extraction, compilation, or executable sink.
ci_capture_canonical_active_upstream_pins() {
    CI_ACTIVE_PIN_ENVOY_VERSION=$ENVOY_VERSION
    CI_ACTIVE_PIN_ENVOY_SOURCE_URL=$ENVOY_SOURCE_URL
    CI_ACTIVE_PIN_ENVOY_ARTIFACT_PLATFORM=$ENVOY_ARTIFACT_PLATFORM
    CI_ACTIVE_PIN_ENVOY_ASSET_NAME=$ENVOY_ASSET_NAME
    CI_ACTIVE_PIN_ENVOY_DOWNLOAD_URL=$ENVOY_DOWNLOAD_URL
    CI_ACTIVE_PIN_ENVOY_SHA256=$ENVOY_SHA256
    CI_ACTIVE_PIN_ENVOY_SHA256_URL=$ENVOY_SHA256_URL
    CI_ACTIVE_PIN_LIGHTTPD_VERSION=$LIGHTTPD_VERSION
    CI_ACTIVE_PIN_LIGHTTPD_SERIES=$LIGHTTPD_SERIES
    CI_ACTIVE_PIN_LIGHTTPD_RELEASE_ROOT_URL=$LIGHTTPD_RELEASE_ROOT_URL
    CI_ACTIVE_PIN_LIGHTTPD_SERIES_BASE_URL=$LIGHTTPD_SERIES_BASE_URL
    CI_ACTIVE_PIN_LIGHTTPD_SOURCE_URL=$LIGHTTPD_SOURCE_URL
    CI_ACTIVE_PIN_LIGHTTPD_ARCHIVE_NAME=$LIGHTTPD_ARCHIVE_NAME
    CI_ACTIVE_PIN_LIGHTTPD_DOWNLOAD_URL=$LIGHTTPD_DOWNLOAD_URL
    CI_ACTIVE_PIN_LIGHTTPD_SHA256=$LIGHTTPD_SHA256
    CI_ACTIVE_PIN_LIGHTTPD_SHA256_URL=$LIGHTTPD_SHA256_URL
    CI_ACTIVE_PIN_CRS_APPROVED_REPO_URL=$CRS_APPROVED_REPO_URL
    CI_ACTIVE_PIN_CRS_RELEASE_TAG=$CRS_RELEASE_TAG
    CI_ACTIVE_PIN_CRS_REPO_URL=$CRS_REPO_URL
    CI_ACTIVE_PIN_CRS_APPROVED_COMMIT=$CRS_APPROVED_COMMIT
    CI_ACTIVE_PIN_CRS_GIT_REF=$CRS_GIT_REF
    CI_ACTIVE_PIN_MODSECURITY_REPO_URL=$MODSECURITY_REPO_URL
    CI_ACTIVE_PIN_MODSECURITY_APPROVED_COMMIT=$MODSECURITY_V3_APPROVED_COMMIT
    CI_ACTIVE_PIN_MODSECURITY_GIT_REF=$MODSECURITY_GIT_REF
    CI_ACTIVE_PIN_MODSECURITY_V3_GIT_URL=$MODSECURITY_V3_GIT_URL
    CI_ACTIVE_PIN_MODSECURITY_V3_GIT_REF=$MODSECURITY_V3_GIT_REF
    CI_ACTIVE_PIN_HTTPD_VERSION=$HTTPD_VERSION
    CI_ACTIVE_PIN_HTTPD_ARCHIVE_NAME=$HTTPD_ARCHIVE_NAME
    CI_ACTIVE_PIN_HTTPD_SOURCE_URL=$HTTPD_SOURCE_URL
    CI_ACTIVE_PIN_HTTPD_SHA256=$HTTPD_SHA256
    CI_ACTIVE_PIN_HTTPD_SHA256_URL=$HTTPD_SHA256_URL
    CI_ACTIVE_PIN_APR_VERSION=$APR_VERSION
    CI_ACTIVE_PIN_APR_ARCHIVE_NAME=$APR_ARCHIVE_NAME
    CI_ACTIVE_PIN_APR_SOURCE_URL=$APR_SOURCE_URL
    CI_ACTIVE_PIN_APR_SHA256=$APR_SHA256
    CI_ACTIVE_PIN_APR_SHA256_URL=$APR_SHA256_URL
    CI_ACTIVE_PIN_APR_UTIL_VERSION=$APR_UTIL_VERSION
    CI_ACTIVE_PIN_APR_UTIL_ARCHIVE_NAME=$APR_UTIL_ARCHIVE_NAME
    CI_ACTIVE_PIN_APR_UTIL_SOURCE_URL=$APR_UTIL_SOURCE_URL
    CI_ACTIVE_PIN_APR_UTIL_SHA256=$APR_UTIL_SHA256
    CI_ACTIVE_PIN_APR_UTIL_SHA256_URL=$APR_UTIL_SHA256_URL
    CI_ACTIVE_PIN_PCRE2_VERSION=$PCRE2_VERSION
    CI_ACTIVE_PIN_PCRE2_ARCHIVE_NAME=$PCRE2_ARCHIVE_NAME
    CI_ACTIVE_PIN_PCRE2_SOURCE_URL=$PCRE2_SOURCE_URL
    CI_ACTIVE_PIN_PCRE2_SHA256=$PCRE2_SHA256
    CI_ACTIVE_PIN_PCRE2_SHA256_URL=$PCRE2_SHA256_URL
    CI_ACTIVE_PIN_NGINX_SOURCE_MODE=$NGINX_SOURCE_MODE
    CI_ACTIVE_PIN_NGINX_SOURCE_REPO_URL=$NGINX_SOURCE_REPO_URL
    CI_ACTIVE_PIN_NGINX_GITHUB_REPO=$NGINX_GITHUB_REPO
    CI_ACTIVE_PIN_NGINX_RELEASE_TAG=$NGINX_RELEASE_TAG
    CI_ACTIVE_PIN_NGINX_SOURCE_GIT_REF=$NGINX_SOURCE_GIT_REF
    CI_ACTIVE_PIN_NGINX_RELEASE_ASSET_NAME=$NGINX_RELEASE_ASSET_NAME
    CI_ACTIVE_PIN_NGINX_DOWNLOAD_URL=$NGINX_DOWNLOAD_URL
    CI_ACTIVE_PIN_NGINX_SHA256=$NGINX_SHA256
    CI_ACTIVE_PIN_NGINX_QUIC_TLS_LIBRARY=$NGINX_QUIC_TLS_LIBRARY
    CI_ACTIVE_PIN_NGINX_QUIC_TLS_VERSION=$NGINX_QUIC_TLS_VERSION
    CI_ACTIVE_PIN_NGINX_QUIC_TLS_ARCHIVE_NAME=$NGINX_QUIC_TLS_ARCHIVE_NAME
    CI_ACTIVE_PIN_NGINX_QUIC_TLS_SOURCE_URL=$NGINX_QUIC_TLS_SOURCE_URL
    CI_ACTIVE_PIN_NGINX_QUIC_TLS_SOURCE_SHA256=$NGINX_QUIC_TLS_SOURCE_SHA256
    CI_ACTIVE_PIN_HAPROXY_VERSION=$HAPROXY_VERSION
    CI_ACTIVE_PIN_HAPROXY_SERIES=$HAPROXY_SERIES
    CI_ACTIVE_PIN_HAPROXY_RELEASE_ROOT_URL=$HAPROXY_RELEASE_ROOT_URL
    CI_ACTIVE_PIN_HAPROXY_SERIES_BASE_URL=$HAPROXY_SERIES_BASE_URL
    CI_ACTIVE_PIN_HAPROXY_ARCHIVE_NAME=$HAPROXY_ARCHIVE_NAME
    CI_ACTIVE_PIN_HAPROXY_SOURCE_URL=$HAPROXY_SOURCE_URL
    CI_ACTIVE_PIN_HAPROXY_SHA256_URL=$HAPROXY_SHA256_URL
    CI_ACTIVE_PIN_HAPROXY_SHA256=$HAPROXY_SHA256
    CI_ACTIVE_PIN_HAPROXY_HTX_VERSION=$HAPROXY_HTX_VERSION
    CI_ACTIVE_PIN_HAPROXY_HTX_SERIES=$HAPROXY_HTX_SERIES
    CI_ACTIVE_PIN_HAPROXY_HTX_SERIES_BASE_URL=$HAPROXY_HTX_SERIES_BASE_URL
    CI_ACTIVE_PIN_HAPROXY_HTX_ARCHIVE_NAME=$HAPROXY_HTX_ARCHIVE_NAME
    CI_ACTIVE_PIN_HAPROXY_HTX_SOURCE_URL=$HAPROXY_HTX_SOURCE_URL
    CI_ACTIVE_PIN_HAPROXY_HTX_SHA256=$HAPROXY_HTX_SHA256
}
ci_capture_canonical_active_upstream_pins

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
    ci_https_url=$1
    case "$ci_https_url" in
        https://*) return 0 ;;
        *) return 1 ;;
    esac
}

# Runtime provenance validation must not resolve checksum tooling through a
# caller-controlled PATH.  The Framework's supported Linux runners provide
# GNU coreutils at one of these fixed system locations; no caller override is
# accepted here.
ci_trusted_sha256_tool() {
    ci_sha_candidate=
    for ci_sha_candidate in /usr/bin/sha256sum /bin/sha256sum; do
        if [ -x "$ci_sha_candidate" ]; then
            printf '%s\n' "$ci_sha_candidate"
            return 0
        fi
    done
    ci_blocked "trusted sha256sum is unavailable at /usr/bin/sha256sum or /bin/sha256sum" >&2
    return 77
}

ci_trusted_sha256_file() {
    ci_sha_file=$1
    ci_sha_tool=$(ci_trusted_sha256_tool) || return 77
    if [ ! -f "$ci_sha_file" ]; then
        ci_blocked "cannot hash a non-regular runtime artifact: $ci_sha_file" >&2
        return 77
    fi
    ci_sha_line=$("$ci_sha_tool" "$ci_sha_file" 2>/dev/null) || {
        ci_blocked "trusted sha256sum failed for runtime artifact: $ci_sha_file" >&2
        return 77
    }
    ci_sha_value=${ci_sha_line%%[[:space:]]*}
    case "$ci_sha_value" in
        *[!0-9A-Fa-f]*|'')
            ci_blocked "trusted sha256sum returned an invalid digest for runtime artifact: $ci_sha_file" >&2
            return 77
            ;;
    esac
    if [ "${#ci_sha_value}" -ne 64 ]; then
        ci_blocked "trusted sha256sum returned a non-SHA-256 digest for runtime artifact: $ci_sha_file" >&2
        return 77
    fi
    printf '%s\n' "$ci_sha_value"
    return 0
}

# Hash a pipeline through the same fixed checksum binary.  This is only for
# deterministic cache/provenance identifiers; release archives themselves
# must use ci_trusted_sha256_file before extraction.
ci_trusted_sha256_stream() {
    ci_sha_tool=$(ci_trusted_sha256_tool) || return 77
    ci_sha_line=$("$ci_sha_tool" 2>/dev/null) || {
        ci_blocked "trusted sha256sum failed for runtime data stream" >&2
        return 77
    }
    ci_sha_value=${ci_sha_line%%[[:space:]]*}
    case "$ci_sha_value" in
        *[!0-9A-Fa-f]*|'')
            ci_blocked "trusted sha256sum returned an invalid digest for runtime data stream" >&2
            return 77
            ;;
    esac
    if [ "${#ci_sha_value}" -ne 64 ]; then
        ci_blocked "trusted sha256sum returned a non-SHA-256 digest for runtime data stream" >&2
        return 77
    fi
    printf '%s\n' "$ci_sha_value"
    return 0
}

ci_safe_url_host() {
    ci_safe_url=$1
    ci_safe_without_scheme=${ci_safe_url#*://}
    ci_safe_without_query=${ci_safe_without_scheme%%[?#]*}
    ci_safe_without_userinfo=${ci_safe_without_query##*@}
    ci_safe_host=${ci_safe_without_userinfo%%/*}
    if [ -z "$ci_safe_host" ]; then
        printf '%s\n' invalid
        return 0
    fi
    printf '%s\n' "$ci_safe_host"
}

ci_require_https_url() {
    ci_url=$1
    ci_label=${2:-url}
    if ci_is_https_url "$ci_url"; then
        return 0
    fi
    ci_blocked "$ci_label must use https:// only (host=$(ci_safe_url_host "$ci_url"))"
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
            ci_blocked "$ci_label must use https://github.com/... only (host=$(ci_safe_url_host "$ci_url"))"
            return 77
            ;;
    esac

    case "$ci_url" in
        *" "*|*"	"*|*"#"*|*"?"*)
            ci_blocked "$ci_label contains invalid characters (host=$(ci_safe_url_host "$ci_url"))"
            return 77
            ;;
    esac

    ci_repo=${ci_url#https://github.com/}
    ci_repo=${ci_repo%.git}
    ci_repo=${ci_repo%/}
    case "$ci_repo" in
        */*/*|/*|*/)
            ci_blocked "$ci_label must be https://github.com/owner/repo only (host=$(ci_safe_url_host "$ci_url"))"
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

    ci_blocked "$ci_label must be https://github.com/owner/repo only (host=$(ci_safe_url_host "$ci_url"))"
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

ci_require_apr_util_pinned_provenance() {
    ci_require_inherited_canonical_upstream_pins || return 77
    if [ "${APR_UTIL_VERSION+x}" = x ]; then
        ci_apr_util_live_version_was_set=1
        ci_apr_util_live_version=$APR_UTIL_VERSION
    else
        ci_apr_util_live_version_was_set=0
        ci_apr_util_live_version=
    fi
    if [ "${APR_UTIL_SOURCE_URL+x}" = x ]; then
        ci_apr_util_live_source_url_was_set=1
        ci_apr_util_live_source_url=$APR_UTIL_SOURCE_URL
    else
        ci_apr_util_live_source_url_was_set=0
        ci_apr_util_live_source_url=
    fi
    if [ "${APR_UTIL_SHA256+x}" = x ]; then
        ci_apr_util_live_sha256_was_set=1
        ci_apr_util_live_sha256=$APR_UTIL_SHA256
    else
        ci_apr_util_live_sha256_was_set=0
        ci_apr_util_live_sha256=
    fi
    if [ "${APR_UTIL_SHA256_URL+x}" = x ]; then
        ci_apr_util_live_sha256_url_was_set=1
        ci_apr_util_live_sha256_url=$APR_UTIL_SHA256_URL
    else
        ci_apr_util_live_sha256_url_was_set=0
        ci_apr_util_live_sha256_url=
    fi

    # Reassert the same parser-visible reviewed tuple before comparing.  This
    # prevents a post-source coherent replacement from becoming the source of
    # truth for the expected URLs or digest.
    ci_apr_util_set_canonical_tuple
    ci_apr_util_expected_source="https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2"
    ci_apr_util_expected_sha_url="$ci_apr_util_expected_source.sha256"

    ci_apr_util_inherited_version_was_set=${CI_APR_UTIL_VERSION_WAS_SET-}
    ci_apr_util_inherited_source_url_was_set=${CI_APR_UTIL_SOURCE_URL_WAS_SET-}
    ci_apr_util_inherited_sha256_was_set=${CI_APR_UTIL_SHA256_WAS_SET-}
    ci_apr_util_inherited_sha256_url_was_set=${CI_APR_UTIL_SHA256_URL_WAS_SET-}
    for ci_apr_util_inherited_flag in \
        "$ci_apr_util_inherited_version_was_set" \
        "$ci_apr_util_inherited_source_url_was_set" \
        "$ci_apr_util_inherited_sha256_was_set" \
        "$ci_apr_util_inherited_sha256_url_was_set"
    do
        case "$ci_apr_util_inherited_flag" in
            0|1) : ;;
            *)
                ci_blocked "APR-util inherited-state snapshot is invalid"
                return 77
                ;;
        esac
    done
    if [ "$ci_apr_util_inherited_version_was_set" = "1" ] && [ "${CI_APR_UTIL_VERSION_BEFORE_SOURCE-}" != "$APR_UTIL_VERSION" ]; then
        ci_blocked "APR_UTIL_VERSION override is not permitted"
        return 77
    fi
    if [ "$ci_apr_util_inherited_source_url_was_set" = "1" ] && [ "${CI_APR_UTIL_SOURCE_URL_BEFORE_SOURCE-}" != "$APR_UTIL_SOURCE_URL" ]; then
        ci_blocked "APR_UTIL_SOURCE_URL override is not permitted"
        return 77
    fi
    if [ "$ci_apr_util_inherited_sha256_was_set" = "1" ] && [ "${CI_APR_UTIL_SHA256_BEFORE_SOURCE-}" != "$APR_UTIL_SHA256" ]; then
        ci_blocked "APR_UTIL_SHA256 override is not permitted"
        return 77
    fi
    if [ "$ci_apr_util_inherited_sha256_url_was_set" = "1" ] && [ "${CI_APR_UTIL_SHA256_URL_BEFORE_SOURCE-}" != "$APR_UTIL_SHA256_URL" ]; then
        ci_blocked "APR_UTIL_SHA256_URL override is not permitted"
        return 77
    fi
    case "$ci_apr_util_inherited_version_was_set:$ci_apr_util_inherited_source_url_was_set:$ci_apr_util_inherited_sha256_was_set:$ci_apr_util_inherited_sha256_url_was_set" in
        0:0:0:0|1:1:1:1) : ;;
        *)
            ci_blocked "APR-util inherited tuple must set all four canonical fields or none"
            return 77
            ;;
    esac
    if [ "$ci_apr_util_live_version_was_set" != "1" ] || [ "$ci_apr_util_live_version" != "$APR_UTIL_VERSION" ]; then
        ci_blocked "APR_UTIL_VERSION must remain the canonical reviewed value"
        return 77
    fi
    if [ "$ci_apr_util_live_source_url_was_set" != "1" ] || [ "$ci_apr_util_live_source_url" != "$APR_UTIL_SOURCE_URL" ]; then
        ci_blocked "APR_UTIL_SOURCE_URL must remain the canonical Apache APR-util asset"
        return 77
    fi
    if [ "$ci_apr_util_live_sha256_was_set" != "1" ] || [ "$ci_apr_util_live_sha256" != "$APR_UTIL_SHA256" ]; then
        ci_blocked "APR_UTIL_SHA256 must remain the canonical reviewed value"
        return 77
    fi
    if [ "$ci_apr_util_live_sha256_url_was_set" != "1" ] || [ "$ci_apr_util_live_sha256_url" != "$APR_UTIL_SHA256_URL" ]; then
        ci_blocked "APR_UTIL_SHA256_URL must remain the canonical APR-util checksum asset"
        return 77
    fi

    case "$APR_UTIL_VERSION" in
        ''|.*|*..*|*[!0123456789.]*)
            ci_blocked "APR_UTIL_VERSION must be a non-empty dotted numeric version: $APR_UTIL_VERSION"
            return 77
            ;;
        *) : ;;
    esac
    if [ "${#APR_UTIL_SHA256}" -ne 64 ]; then
        ci_blocked "APR_UTIL_SHA256 must contain exactly 64 hexadecimal characters"
        return 77
    fi
    case "$APR_UTIL_SHA256" in
        *[!0123456789abcdefABCDEF]*)
            ci_blocked "APR_UTIL_SHA256 must contain exactly 64 hexadecimal characters"
            return 77
            ;;
        *) : ;;
    esac
    if [ "$APR_UTIL_SOURCE_URL" != "$ci_apr_util_expected_source" ]; then
        ci_blocked "APR_UTIL_SOURCE_URL must be the canonical Apache APR-util asset: $APR_UTIL_SOURCE_URL"
        return 77
    fi
    if [ "$APR_UTIL_SHA256_URL" != "$ci_apr_util_expected_sha_url" ]; then
        ci_blocked "APR_UTIL_SHA256_URL must name the canonical APR-util asset checksum: $APR_UTIL_SHA256_URL"
        return 77
    fi
    ci_require_https_url "$APR_UTIL_SOURCE_URL" APR_UTIL_SOURCE_URL || return 77
    ci_require_https_url "$APR_UTIL_SHA256_URL" APR_UTIL_SHA256_URL || return 77
    return 0
}

ci_require_traefik_pinned_provenance() {
    ci_require_inherited_canonical_upstream_pins || return 77
    if [ "${TRAEFIK_VERSION+x}" = x ]; then
        ci_traefik_live_version_was_set=1
        ci_traefik_live_version=$TRAEFIK_VERSION
    else
        ci_traefik_live_version_was_set=0
        ci_traefik_live_version=
    fi
    if [ "${TRAEFIK_SOURCE_URL+x}" = x ]; then
        ci_traefik_live_source_url_was_set=1
        ci_traefik_live_source_url=$TRAEFIK_SOURCE_URL
    else
        ci_traefik_live_source_url_was_set=0
        ci_traefik_live_source_url=
    fi
    if [ "${TRAEFIK_DOWNLOAD_URL+x}" = x ]; then
        ci_traefik_live_download_url_was_set=1
        ci_traefik_live_download_url=$TRAEFIK_DOWNLOAD_URL
    else
        ci_traefik_live_download_url_was_set=0
        ci_traefik_live_download_url=
    fi
    if [ "${TRAEFIK_SHA256+x}" = x ]; then
        ci_traefik_live_sha256_was_set=1
        ci_traefik_live_sha256=$TRAEFIK_SHA256
    else
        ci_traefik_live_sha256_was_set=0
        ci_traefik_live_sha256=
    fi
    if [ "${TRAEFIK_SHA256_URL+x}" = x ]; then
        ci_traefik_live_sha256_url_was_set=1
        ci_traefik_live_sha256_url=$TRAEFIK_SHA256_URL
    else
        ci_traefik_live_sha256_url_was_set=0
        ci_traefik_live_sha256_url=
    fi
    if [ "${TRAEFIK_ARTIFACT_PLATFORM+x}" = x ]; then
        ci_traefik_live_artifact_platform_was_set=1
        ci_traefik_live_artifact_platform=$TRAEFIK_ARTIFACT_PLATFORM
    else
        ci_traefik_live_artifact_platform_was_set=0
        ci_traefik_live_artifact_platform=
    fi
    if [ "${TRAEFIK_ARCHIVE_NAME+x}" = x ]; then
        ci_traefik_live_archive_name_was_set=1
        ci_traefik_live_archive_name=$TRAEFIK_ARCHIVE_NAME
    else
        ci_traefik_live_archive_name_was_set=0
        ci_traefik_live_archive_name=
    fi
    if [ "${TRAEFIK_BIN+x}" = x ]; then
        ci_traefik_live_bin_was_set=1
        ci_traefik_live_bin=$TRAEFIK_BIN
    else
        ci_traefik_live_bin_was_set=0
        ci_traefik_live_bin=
    fi
    if [ "${TRAEFIK_ARCHIVE+x}" = x ]; then
        ci_traefik_live_archive_was_set=1
        ci_traefik_live_archive=$TRAEFIK_ARCHIVE
    else
        ci_traefik_live_archive_was_set=0
        ci_traefik_live_archive=
    fi

    # Reassert the parser-visible reviewed tuple before comparing.  This
    # prevents a post-source coherent replacement from becoming the source of
    # truth for the archive identity or digest.
    ci_traefik_set_canonical_tuple
    ci_traefik_expected_archive_name="traefik_v${TRAEFIK_VERSION}_${TRAEFIK_ARTIFACT_PLATFORM}.tar.gz"
    ci_traefik_expected_download_url="$TRAEFIK_SOURCE_URL/download/v$TRAEFIK_VERSION/$ci_traefik_expected_archive_name"
    ci_traefik_expected_sha256_url="$TRAEFIK_SOURCE_URL/download/v$TRAEFIK_VERSION/traefik_v${TRAEFIK_VERSION}_checksums.txt"
    ci_traefik_expected_bin="$TRAEFIK_BUILD_ROOT/bin/traefik"
    ci_traefik_expected_archive="$TRAEFIK_COMPONENT_ROOT/downloads/$ci_traefik_expected_archive_name"

    ci_traefik_inherited_version_was_set=${CI_TRAEFIK_VERSION_WAS_SET-}
    ci_traefik_inherited_source_url_was_set=${CI_TRAEFIK_SOURCE_URL_WAS_SET-}
    ci_traefik_inherited_download_url_was_set=${CI_TRAEFIK_DOWNLOAD_URL_WAS_SET-}
    ci_traefik_inherited_sha256_was_set=${CI_TRAEFIK_SHA256_WAS_SET-}
    ci_traefik_inherited_sha256_url_was_set=${CI_TRAEFIK_SHA256_URL_WAS_SET-}
    ci_traefik_inherited_artifact_platform_was_set=${CI_TRAEFIK_ARTIFACT_PLATFORM_WAS_SET-}
    ci_traefik_inherited_archive_name_was_set=${CI_TRAEFIK_ARCHIVE_NAME_WAS_SET-}
    for ci_traefik_inherited_flag in \
        "$ci_traefik_inherited_version_was_set" \
        "$ci_traefik_inherited_source_url_was_set" \
        "$ci_traefik_inherited_download_url_was_set" \
        "$ci_traefik_inherited_sha256_was_set" \
        "$ci_traefik_inherited_sha256_url_was_set" \
        "$ci_traefik_inherited_artifact_platform_was_set" \
        "$ci_traefik_inherited_archive_name_was_set"
    do
        case "$ci_traefik_inherited_flag" in
            0|1) : ;;
            *)
                ci_blocked "Traefik inherited-state snapshot is invalid"
                return 77
                ;;
        esac
    done
    if [ "$ci_traefik_inherited_version_was_set" = "1" ] && [ "${CI_TRAEFIK_VERSION_BEFORE_SOURCE-}" != "$TRAEFIK_VERSION" ]; then
        ci_blocked "TRAEFIK_VERSION override is not permitted"
        return 77
    fi
    if [ "$ci_traefik_inherited_source_url_was_set" = "1" ] && [ "${CI_TRAEFIK_SOURCE_URL_BEFORE_SOURCE-}" != "$TRAEFIK_SOURCE_URL" ]; then
        ci_blocked "TRAEFIK_SOURCE_URL override is not permitted"
        return 77
    fi
    if [ "$ci_traefik_inherited_download_url_was_set" = "1" ] && [ "${CI_TRAEFIK_DOWNLOAD_URL_BEFORE_SOURCE-}" != "$ci_traefik_expected_download_url" ]; then
        ci_blocked "TRAEFIK_DOWNLOAD_URL override is not permitted"
        return 77
    fi
    if [ "$ci_traefik_inherited_sha256_was_set" = "1" ] && [ "${CI_TRAEFIK_SHA256_BEFORE_SOURCE-}" != "$TRAEFIK_SHA256" ]; then
        ci_blocked "TRAEFIK_SHA256 override is not permitted"
        return 77
    fi
    if [ "$ci_traefik_inherited_sha256_url_was_set" = "1" ] && [ "${CI_TRAEFIK_SHA256_URL_BEFORE_SOURCE-}" != "$ci_traefik_expected_sha256_url" ]; then
        ci_blocked "TRAEFIK_SHA256_URL override is not permitted"
        return 77
    fi
    if [ "$ci_traefik_inherited_artifact_platform_was_set" = "1" ] && [ "${CI_TRAEFIK_ARTIFACT_PLATFORM_BEFORE_SOURCE-}" != "$TRAEFIK_ARTIFACT_PLATFORM" ]; then
        ci_blocked "TRAEFIK_ARTIFACT_PLATFORM override is not permitted"
        return 77
    fi
    if [ "$ci_traefik_inherited_archive_name_was_set" = "1" ] && [ "${CI_TRAEFIK_ARCHIVE_NAME_BEFORE_SOURCE-}" != "$ci_traefik_expected_archive_name" ]; then
        ci_blocked "TRAEFIK_ARCHIVE_NAME override is not permitted"
        return 77
    fi
    case "$ci_traefik_inherited_version_was_set:$ci_traefik_inherited_source_url_was_set:$ci_traefik_inherited_download_url_was_set:$ci_traefik_inherited_sha256_was_set:$ci_traefik_inherited_sha256_url_was_set:$ci_traefik_inherited_artifact_platform_was_set:$ci_traefik_inherited_archive_name_was_set" in
        0:0:0:0:0:0:0|1:1:1:1:1:1:1) : ;;
        *)
            ci_blocked "Traefik inherited tuple must set all seven canonical fields or none"
            return 77
            ;;
    esac

    case "${CI_TRAEFIK_BIN_WAS_SET-}" in
        0|1) : ;;
        *)
            ci_blocked "Traefik binary inherited-state snapshot is invalid"
            return 77
            ;;
    esac
    if [ "${CI_TRAEFIK_BIN_WAS_SET-}" = "1" ] && [ "${CI_TRAEFIK_BIN_BEFORE_SOURCE-}" != "$ci_traefik_expected_bin" ]; then
        ci_blocked "TRAEFIK_BIN override is not permitted; stage the verified canonical archive instead"
        return 77
    fi

    if [ "$ci_traefik_live_version_was_set" != "1" ] || [ "$ci_traefik_live_version" != "$TRAEFIK_VERSION" ]; then
        ci_blocked "TRAEFIK_VERSION must remain the canonical reviewed value"
        return 77
    fi
    if [ "$ci_traefik_live_source_url_was_set" != "1" ] || [ "$ci_traefik_live_source_url" != "$TRAEFIK_SOURCE_URL" ]; then
        ci_blocked "TRAEFIK_SOURCE_URL must remain the canonical Traefik release endpoint"
        return 77
    fi
    if [ "$ci_traefik_live_download_url_was_set" != "1" ] || [ "$ci_traefik_live_download_url" != "$ci_traefik_expected_download_url" ]; then
        ci_blocked "TRAEFIK_DOWNLOAD_URL must name the canonical Traefik archive"
        return 77
    fi
    if [ "$ci_traefik_live_sha256_was_set" != "1" ] || [ "$ci_traefik_live_sha256" != "$TRAEFIK_SHA256" ]; then
        ci_blocked "TRAEFIK_SHA256 must remain the canonical reviewed archive digest"
        return 77
    fi
    if [ "$ci_traefik_live_sha256_url_was_set" != "1" ] || [ "$ci_traefik_live_sha256_url" != "$ci_traefik_expected_sha256_url" ]; then
        ci_blocked "TRAEFIK_SHA256_URL must name the canonical Traefik checksum asset"
        return 77
    fi
    if [ "$ci_traefik_live_artifact_platform_was_set" != "1" ] || [ "$ci_traefik_live_artifact_platform" != "$TRAEFIK_ARTIFACT_PLATFORM" ]; then
        ci_blocked "TRAEFIK_ARTIFACT_PLATFORM must remain the canonical linux_amd64 archive platform"
        return 77
    fi
    if [ "$ci_traefik_live_archive_name_was_set" != "1" ] || [ "$ci_traefik_live_archive_name" != "$ci_traefik_expected_archive_name" ]; then
        ci_blocked "TRAEFIK_ARCHIVE_NAME must remain the canonical Traefik archive name"
        return 77
    fi
    if [ "$ci_traefik_live_bin_was_set" != "1" ] || [ "$ci_traefik_live_bin" != "$ci_traefik_expected_bin" ]; then
        ci_blocked "TRAEFIK_BIN must remain the canonical task-private destination"
        return 77
    fi
    if [ "$ci_traefik_live_archive_was_set" != "1" ] || [ "$ci_traefik_live_archive" != "$ci_traefik_expected_archive" ]; then
        ci_blocked "TRAEFIK_ARCHIVE must remain the canonical verified-cache archive path"
        return 77
    fi

    case "$TRAEFIK_VERSION" in
        ''|.*|*..*|*[!0123456789.]*)
            ci_blocked "TRAEFIK_VERSION must be a non-empty dotted numeric version: $TRAEFIK_VERSION"
            return 77
            ;;
        *) : ;;
    esac
    if [ "${#TRAEFIK_SHA256}" -ne 64 ]; then
        ci_blocked "TRAEFIK_SHA256 must contain exactly 64 hexadecimal characters"
        return 77
    fi
    case "$TRAEFIK_SHA256" in
        *[!0123456789abcdefABCDEF]*)
            ci_blocked "TRAEFIK_SHA256 must contain exactly 64 hexadecimal characters"
            return 77
            ;;
        *) : ;;
    esac
    if [ "$TRAEFIK_ARTIFACT_PLATFORM" != "linux_amd64" ]; then
        ci_blocked "TRAEFIK_ARTIFACT_PLATFORM must be linux_amd64 for the reviewed archive: $TRAEFIK_ARTIFACT_PLATFORM"
        return 77
    fi
    if [ "$TRAEFIK_ARCHIVE_NAME" != "$ci_traefik_expected_archive_name" ]; then
        ci_blocked "TRAEFIK_ARCHIVE_NAME expected $ci_traefik_expected_archive_name, got $TRAEFIK_ARCHIVE_NAME"
        return 77
    fi
    if [ "$TRAEFIK_DOWNLOAD_URL" != "$ci_traefik_expected_download_url" ]; then
        ci_blocked "TRAEFIK_DOWNLOAD_URL expected $ci_traefik_expected_download_url, got $TRAEFIK_DOWNLOAD_URL"
        return 77
    fi
    if [ "$TRAEFIK_SHA256_URL" != "$ci_traefik_expected_sha256_url" ]; then
        ci_blocked "TRAEFIK_SHA256_URL expected $ci_traefik_expected_sha256_url, got $TRAEFIK_SHA256_URL"
        return 77
    fi
    ci_require_https_url "$TRAEFIK_SOURCE_URL" TRAEFIK_SOURCE_URL || return 77
    ci_require_https_url "$TRAEFIK_INSTALL_DOCS_URL" TRAEFIK_INSTALL_DOCS_URL || return 77
    ci_require_https_url "$TRAEFIK_DOWNLOAD_URL" TRAEFIK_DOWNLOAD_URL || return 77
    ci_require_https_url "$TRAEFIK_SHA256_URL" TRAEFIK_SHA256_URL || return 77
    return 0
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

# Go-FTW and Albedo are supplied by locally probed binaries today, but their
# maintenance provenance is still a canonical release tuple.  This keeps the
# only manually maintained tag and immutable commit in common.sh while the
# compatibility aliases remain derived, never independently edited pins.
ci_require_release_tag_commit_tuple() {
    ci_tuple_label=$1
    ci_tuple_tag=$2
    ci_tuple_ref=$3
    ci_tuple_alias=$4
    ci_tuple_commit=$5
    ci_tuple_version=${ci_tuple_tag#v}
    if [ "$ci_tuple_version" = "$ci_tuple_tag" ]; then
        ci_blocked "$ci_tuple_label release tag must begin with v"
        return 77
    fi
    case "$ci_tuple_version" in
        ''|.*|*..*|*[!0123456789.]*)
            ci_blocked "$ci_tuple_label release tag must be a stable dotted numeric version"
            return 77
            ;;
        *) : ;;
    esac
    if [ "$ci_tuple_ref" != "$ci_tuple_tag" ] || [ "$ci_tuple_alias" != "$ci_tuple_tag" ]; then
        ci_blocked "$ci_tuple_label ref and compatibility alias must be derived from its release tag"
        return 77
    fi
    if [ "${#ci_tuple_commit}" -ne 40 ]; then
        ci_blocked "$ci_tuple_label approved commit must be a full 40-character SHA-1"
        return 77
    fi
    case "$ci_tuple_commit" in
        *[!0123456789abcdef]*)
            ci_blocked "$ci_tuple_label approved commit must be lowercase hexadecimal"
            return 77
            ;;
        *) : ;;
    esac
    return 0
}

ci_validate_global_maintenance_pin_config() {
    ci_require_release_tag_commit_tuple \
        GO_FTW "$GO_FTW_RELEASE_TAG" "$GO_FTW_GIT_REF" \
        "$GO_FTW_PROMPT_EXPECTED_LATEST" "$GO_FTW_APPROVED_COMMIT" || return 77
    ci_require_release_tag_commit_tuple \
        ALBEDO "$ALBEDO_RELEASE_TAG" "$ALBEDO_GIT_REF" \
        "$ALBEDO_PROMPT_EXPECTED_LATEST" "$ALBEDO_APPROVED_COMMIT" || return 77
    return 0
}

ci_require_canonical_active_pin() {
    ci_active_pin_label=$1
    ci_active_pin_value=$2
    ci_active_pin_expected=$3
    if [ "$ci_active_pin_value" != "$ci_active_pin_expected" ]; then
        if [ "$ci_active_pin_label" = "APR_UTIL_VERSION" ]; then
            ci_blocked "APR_UTIL_VERSION must remain the canonical reviewed value (differs from the canonical common.sh pin)"
            return 77
        fi
        ci_blocked "$ci_active_pin_label differs from the canonical common.sh pin"
        return 77
    fi
    return 0
}

# Release-series declarations are part of the reviewed source identity.  A
# mismatch must fail before a caller can use a runtime cache, download, or
# build.  Keep this check POSIX and independent of any shell evaluation.
ci_require_runtime_series_version() {
    ci_series=$1
    ci_version=$2
    ci_label=${3:-runtime}
    case "$ci_series" in
        ''|*[!0-9.]*|.*|*.|*.*.*)
            ci_blocked "$ci_label series is not a numeric major.minor value"
            return 77
            ;;
    esac
    case "$ci_version" in
        ''|*[!0-9.]*|*.*.*.*)
            ci_blocked "$ci_label version is not a numeric release"
            return 77
            ;;
    esac
    case "$ci_version" in
        "$ci_series".[0-9]*) return 0 ;;
        *)
            ci_blocked "$ci_label version $ci_version does not match declared series $ci_series"
            return 77
            ;;
    esac
}

ci_validate_runtime_series_config() {
    ci_require_runtime_series_version "$LIGHTTPD_SERIES" "$LIGHTTPD_VERSION" LIGHTTPD || return 77
    ci_require_runtime_series_version "$HAPROXY_SERIES" "$HAPROXY_VERSION" HAPROXY || return 77
    ci_require_runtime_series_version "$HAPROXY_HTX_SERIES" "$HAPROXY_HTX_VERSION" HAPROXY_HTX || return 77
    [ "$LIGHTTPD_SOURCE_URL" = "$LIGHTTPD_SERIES_BASE_URL/" ] || {
        ci_blocked "LIGHTTPD_SOURCE_URL is not derived from LIGHTTPD_SERIES_BASE_URL"
        return 77
    }
    [ "$LIGHTTPD_LATEST_URL" = "$LIGHTTPD_SERIES_BASE_URL/latest.txt" ] || {
        ci_blocked "LIGHTTPD_LATEST_URL is not derived from LIGHTTPD_SERIES_BASE_URL"
        return 77
    }
    ci_lighttpd_latest_path=${LIGHTTPD_LATEST_URL#*://}
    case "$ci_lighttpd_latest_path" in
        *//* )
            ci_blocked "LIGHTTPD_LATEST_URL contains a double slash"
            return 77
            ;;
    esac
    [ "$HAPROXY_SOURCE_URL" = "$HAPROXY_SERIES_BASE_URL/$HAPROXY_ARCHIVE_NAME" ] || {
        ci_blocked "HAPROXY_SOURCE_URL is not derived from HAPROXY_SERIES_BASE_URL"
        return 77
    }
    [ "$HAPROXY_HTX_SOURCE_URL" = "$HAPROXY_HTX_SERIES_BASE_URL/$HAPROXY_HTX_ARCHIVE_NAME" ] || {
        ci_blocked "HAPROXY_HTX_SOURCE_URL is not derived from HAPROXY_HTX_SERIES_BASE_URL"
        return 77
    }
    return 0
}

ci_require_inherited_canonical_pin() {
    ci_inherited_pin_name=$1
    ci_inherited_pin_expected=$2
    ci_inherited_pin_line=$(printf '%s\n' "$CI_INHERITED_UPSTREAM_ENV" | awk -v key="$ci_inherited_pin_name" '
        index($0, key "=") == 1 {
            count++
            line = $0
        }
        END {
            if (count > 1) {
                exit 2
            }
            if (count == 1) {
                print line
            }
        }
    ')
    ci_inherited_pin_status=$?
    if [ "$ci_inherited_pin_status" -eq 2 ]; then
        ci_blocked "$ci_inherited_pin_name is duplicated in the inherited environment"
        return 77
    fi
    if [ "$ci_inherited_pin_status" -ne 0 ]; then
        ci_blocked "$ci_inherited_pin_name inherited-state snapshot is invalid"
        return 77
    fi
    if [ -z "$ci_inherited_pin_line" ]; then
        return 0
    fi
    ci_inherited_pin_value=${ci_inherited_pin_line#*=}
    case "$ci_inherited_pin_name:$ci_inherited_pin_value" in
        MODSECURITY_REPO_URL:|MODSECURITY_GIT_REF:|MODSECURITY_V3_GIT_URL:|MODSECURITY_V3_GIT_REF:)
            # Empty legacy aliases are compatibility metadata.  common.sh
            # normalizes them to the reviewed v3 tuple; only non-empty caller
            # values are treated as attempted source-identity overrides.
            return 0
            ;;
    esac
    if [ "$ci_inherited_pin_value" != "$ci_inherited_pin_expected" ]; then
        ci_blocked "$ci_inherited_pin_name override is not permitted"
        return 77
    fi
    return 0
}

ci_require_inherited_canonical_upstream_pins() {
    if [ "${CI_INHERITED_UPSTREAM_ENV_STATUS:-77}" -ne 0 ]; then
        ci_blocked "trusted env is unavailable for inherited active-pin validation"
        return 77
    fi
    # Keep this list aligned with the canonical active-pin arguments below.
    # Entries use the first ':' only as a separator; the reviewed URLs retain
    # their embedded ':' and are never interpreted.
    for ci_inherited_pin_entry in \
        "ENVOY_VERSION:$ENVOY_VERSION" \
        "ENVOY_SOURCE_URL:$ENVOY_SOURCE_URL" \
        "ENVOY_ARTIFACT_PLATFORM:$ENVOY_ARTIFACT_PLATFORM" \
        "ENVOY_ASSET_NAME:$ENVOY_ASSET_NAME" \
        "ENVOY_DOWNLOAD_URL:$ENVOY_DOWNLOAD_URL" \
        "ENVOY_SHA256:$ENVOY_SHA256" \
        "ENVOY_SHA256_URL:$ENVOY_SHA256_URL" \
        "LIGHTTPD_VERSION:$LIGHTTPD_VERSION" \
        "LIGHTTPD_SERIES:$LIGHTTPD_SERIES" \
        "LIGHTTPD_RELEASE_ROOT_URL:$LIGHTTPD_RELEASE_ROOT_URL" \
        "LIGHTTPD_SERIES_BASE_URL:$LIGHTTPD_SERIES_BASE_URL" \
        "LIGHTTPD_SOURCE_URL:$LIGHTTPD_SOURCE_URL" \
        "LIGHTTPD_ARCHIVE_NAME:$LIGHTTPD_ARCHIVE_NAME" \
        "LIGHTTPD_DOWNLOAD_URL:$LIGHTTPD_DOWNLOAD_URL" \
        "LIGHTTPD_SHA256:$LIGHTTPD_SHA256" \
        "LIGHTTPD_SHA256_URL:$LIGHTTPD_SHA256_URL" \
        "CRS_APPROVED_REPO_URL:$CRS_APPROVED_REPO_URL" \
        "CRS_RELEASE_TAG:$CRS_RELEASE_TAG" \
        "CRS_REPO_URL:$CRS_REPO_URL" \
        "CRS_APPROVED_COMMIT:$CRS_APPROVED_COMMIT" \
        "CRS_GIT_REF:$CRS_GIT_REF" \
        "MODSECURITY_REPO_URL:$MODSECURITY_REPO_URL" \
        "MODSECURITY_V3_APPROVED_COMMIT:$MODSECURITY_V3_APPROVED_COMMIT" \
        "MODSECURITY_GIT_REF:$MODSECURITY_GIT_REF" \
        "MODSECURITY_V3_GIT_URL:$MODSECURITY_V3_GIT_URL" \
        "MODSECURITY_V3_GIT_REF:$MODSECURITY_V3_GIT_REF" \
        "HTTPD_VERSION:$HTTPD_VERSION" \
        "HTTPD_ARCHIVE_NAME:$HTTPD_ARCHIVE_NAME" \
        "HTTPD_SOURCE_URL:$HTTPD_SOURCE_URL" \
        "HTTPD_SHA256:$HTTPD_SHA256" \
        "HTTPD_SHA256_URL:$HTTPD_SHA256_URL" \
        "APR_VERSION:$APR_VERSION" \
        "APR_ARCHIVE_NAME:$APR_ARCHIVE_NAME" \
        "APR_SOURCE_URL:$APR_SOURCE_URL" \
        "APR_SHA256:$APR_SHA256" \
        "APR_SHA256_URL:$APR_SHA256_URL" \
        "APR_UTIL_VERSION:$APR_UTIL_VERSION" \
        "APR_UTIL_ARCHIVE_NAME:$APR_UTIL_ARCHIVE_NAME" \
        "APR_UTIL_SOURCE_URL:$APR_UTIL_SOURCE_URL" \
        "APR_UTIL_SHA256:$APR_UTIL_SHA256" \
        "APR_UTIL_SHA256_URL:$APR_UTIL_SHA256_URL" \
        "PCRE2_VERSION:$PCRE2_VERSION" \
        "PCRE2_ARCHIVE_NAME:$PCRE2_ARCHIVE_NAME" \
        "PCRE2_SOURCE_URL:$PCRE2_SOURCE_URL" \
        "PCRE2_SHA256:$PCRE2_SHA256" \
        "PCRE2_SHA256_URL:$PCRE2_SHA256_URL" \
        "NGINX_SOURCE_MODE:$NGINX_SOURCE_MODE" \
        "NGINX_SOURCE_REPO_URL:$NGINX_SOURCE_REPO_URL" \
        "NGINX_GITHUB_REPO:$NGINX_GITHUB_REPO" \
        "NGINX_RELEASE_TAG:$NGINX_RELEASE_TAG" \
        "NGINX_SOURCE_GIT_REF:$NGINX_SOURCE_GIT_REF" \
        "NGINX_RELEASE_ASSET_NAME:$NGINX_RELEASE_ASSET_NAME" \
        "NGINX_DOWNLOAD_URL:$NGINX_DOWNLOAD_URL" \
        "NGINX_SHA256:$NGINX_SHA256" \
        "NGINX_QUIC_TLS_LIBRARY:$NGINX_QUIC_TLS_LIBRARY" \
        "NGINX_QUIC_TLS_VERSION:$NGINX_QUIC_TLS_VERSION" \
        "NGINX_QUIC_TLS_ARCHIVE_NAME:$NGINX_QUIC_TLS_ARCHIVE_NAME" \
        "NGINX_QUIC_TLS_SOURCE_URL:$NGINX_QUIC_TLS_SOURCE_URL" \
        "NGINX_QUIC_TLS_SOURCE_SHA256:$NGINX_QUIC_TLS_SOURCE_SHA256" \
        "HAPROXY_VERSION:$HAPROXY_VERSION" \
        "HAPROXY_SERIES:$HAPROXY_SERIES" \
        "HAPROXY_RELEASE_ROOT_URL:$HAPROXY_RELEASE_ROOT_URL" \
        "HAPROXY_SERIES_BASE_URL:$HAPROXY_SERIES_BASE_URL" \
        "HAPROXY_ARCHIVE_NAME:$HAPROXY_ARCHIVE_NAME" \
        "HAPROXY_SOURCE_URL:$HAPROXY_SOURCE_URL" \
        "HAPROXY_SHA256_URL:$HAPROXY_SHA256_URL" \
        "HAPROXY_SHA256:$HAPROXY_SHA256" \
        "HAPROXY_HTX_VERSION:$HAPROXY_HTX_VERSION" \
        "HAPROXY_HTX_SERIES:$HAPROXY_HTX_SERIES" \
        "HAPROXY_HTX_SERIES_BASE_URL:$HAPROXY_HTX_SERIES_BASE_URL" \
        "HAPROXY_HTX_ARCHIVE_NAME:$HAPROXY_HTX_ARCHIVE_NAME" \
        "HAPROXY_HTX_SOURCE_URL:$HAPROXY_HTX_SOURCE_URL" \
        "HAPROXY_HTX_SHA256:$HAPROXY_HTX_SHA256"
    do
        ci_inherited_pin_name=${ci_inherited_pin_entry%%:*}
        ci_inherited_pin_expected=${ci_inherited_pin_entry#*:}
        ci_require_inherited_canonical_pin "$ci_inherited_pin_name" "$ci_inherited_pin_expected" || return 77
    done
    return 0
}

ci_require_canonical_active_upstream_pins() {
    ci_validate_runtime_series_config || return 77
    ci_require_inherited_canonical_upstream_pins || return 77
    ci_require_canonical_active_pin ENVOY_VERSION "$ENVOY_VERSION" "$CI_ACTIVE_PIN_ENVOY_VERSION" || return 77
    ci_require_canonical_active_pin ENVOY_SOURCE_URL "$ENVOY_SOURCE_URL" "$CI_ACTIVE_PIN_ENVOY_SOURCE_URL" || return 77
    ci_require_canonical_active_pin ENVOY_ARTIFACT_PLATFORM "$ENVOY_ARTIFACT_PLATFORM" "$CI_ACTIVE_PIN_ENVOY_ARTIFACT_PLATFORM" || return 77
    ci_require_canonical_active_pin ENVOY_ASSET_NAME "$ENVOY_ASSET_NAME" "$CI_ACTIVE_PIN_ENVOY_ASSET_NAME" || return 77
    ci_require_canonical_active_pin ENVOY_DOWNLOAD_URL "$ENVOY_DOWNLOAD_URL" "$CI_ACTIVE_PIN_ENVOY_DOWNLOAD_URL" || return 77
    ci_require_canonical_active_pin ENVOY_SHA256 "$ENVOY_SHA256" "$CI_ACTIVE_PIN_ENVOY_SHA256" || return 77
    ci_require_canonical_active_pin ENVOY_SHA256_URL "$ENVOY_SHA256_URL" "$CI_ACTIVE_PIN_ENVOY_SHA256_URL" || return 77
    ci_require_canonical_active_pin LIGHTTPD_VERSION "$LIGHTTPD_VERSION" "$CI_ACTIVE_PIN_LIGHTTPD_VERSION" || return 77
    ci_require_canonical_active_pin LIGHTTPD_SERIES "$LIGHTTPD_SERIES" "$CI_ACTIVE_PIN_LIGHTTPD_SERIES" || return 77
    ci_require_canonical_active_pin LIGHTTPD_RELEASE_ROOT_URL "$LIGHTTPD_RELEASE_ROOT_URL" "$CI_ACTIVE_PIN_LIGHTTPD_RELEASE_ROOT_URL" || return 77
    ci_require_canonical_active_pin LIGHTTPD_SERIES_BASE_URL "$LIGHTTPD_SERIES_BASE_URL" "$CI_ACTIVE_PIN_LIGHTTPD_SERIES_BASE_URL" || return 77
    ci_require_canonical_active_pin LIGHTTPD_SOURCE_URL "$LIGHTTPD_SOURCE_URL" "$CI_ACTIVE_PIN_LIGHTTPD_SOURCE_URL" || return 77
    ci_require_canonical_active_pin LIGHTTPD_ARCHIVE_NAME "$LIGHTTPD_ARCHIVE_NAME" "$CI_ACTIVE_PIN_LIGHTTPD_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin LIGHTTPD_DOWNLOAD_URL "$LIGHTTPD_DOWNLOAD_URL" "$CI_ACTIVE_PIN_LIGHTTPD_DOWNLOAD_URL" || return 77
    ci_require_canonical_active_pin LIGHTTPD_SHA256 "$LIGHTTPD_SHA256" "$CI_ACTIVE_PIN_LIGHTTPD_SHA256" || return 77
    ci_require_canonical_active_pin LIGHTTPD_SHA256_URL "$LIGHTTPD_SHA256_URL" "$CI_ACTIVE_PIN_LIGHTTPD_SHA256_URL" || return 77
    ci_require_canonical_active_pin CRS_APPROVED_REPO_URL "$CRS_APPROVED_REPO_URL" "$CI_ACTIVE_PIN_CRS_APPROVED_REPO_URL" || return 77
    ci_require_canonical_active_pin CRS_RELEASE_TAG "$CRS_RELEASE_TAG" "$CI_ACTIVE_PIN_CRS_RELEASE_TAG" || return 77
    ci_require_canonical_active_pin CRS_REPO_URL "$CRS_REPO_URL" "$CI_ACTIVE_PIN_CRS_REPO_URL" || return 77
    ci_require_canonical_active_pin CRS_APPROVED_COMMIT "$CRS_APPROVED_COMMIT" "$CI_ACTIVE_PIN_CRS_APPROVED_COMMIT" || return 77
    ci_require_canonical_active_pin CRS_GIT_REF "$CRS_GIT_REF" "$CI_ACTIVE_PIN_CRS_GIT_REF" || return 77
    ci_require_canonical_active_pin MODSECURITY_REPO_URL "$MODSECURITY_REPO_URL" "$CI_ACTIVE_PIN_MODSECURITY_REPO_URL" || return 77
    ci_require_canonical_active_pin MODSECURITY_V3_APPROVED_COMMIT "$MODSECURITY_V3_APPROVED_COMMIT" "$CI_ACTIVE_PIN_MODSECURITY_APPROVED_COMMIT" || return 77
    ci_require_canonical_active_pin MODSECURITY_GIT_REF "$MODSECURITY_GIT_REF" "$CI_ACTIVE_PIN_MODSECURITY_GIT_REF" || return 77
    ci_require_canonical_active_pin MODSECURITY_V3_GIT_URL "$MODSECURITY_V3_GIT_URL" "$CI_ACTIVE_PIN_MODSECURITY_V3_GIT_URL" || return 77
    ci_require_canonical_active_pin MODSECURITY_V3_GIT_REF "$MODSECURITY_V3_GIT_REF" "$CI_ACTIVE_PIN_MODSECURITY_V3_GIT_REF" || return 77
    ci_require_canonical_active_pin HTTPD_VERSION "$HTTPD_VERSION" "$CI_ACTIVE_PIN_HTTPD_VERSION" || return 77
    ci_require_canonical_active_pin HTTPD_ARCHIVE_NAME "$HTTPD_ARCHIVE_NAME" "$CI_ACTIVE_PIN_HTTPD_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin HTTPD_SOURCE_URL "$HTTPD_SOURCE_URL" "$CI_ACTIVE_PIN_HTTPD_SOURCE_URL" || return 77
    ci_require_canonical_active_pin HTTPD_SHA256 "$HTTPD_SHA256" "$CI_ACTIVE_PIN_HTTPD_SHA256" || return 77
    ci_require_canonical_active_pin HTTPD_SHA256_URL "$HTTPD_SHA256_URL" "$CI_ACTIVE_PIN_HTTPD_SHA256_URL" || return 77
    ci_require_canonical_active_pin APR_VERSION "$APR_VERSION" "$CI_ACTIVE_PIN_APR_VERSION" || return 77
    ci_require_canonical_active_pin APR_ARCHIVE_NAME "$APR_ARCHIVE_NAME" "$CI_ACTIVE_PIN_APR_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin APR_SOURCE_URL "$APR_SOURCE_URL" "$CI_ACTIVE_PIN_APR_SOURCE_URL" || return 77
    ci_require_canonical_active_pin APR_SHA256 "$APR_SHA256" "$CI_ACTIVE_PIN_APR_SHA256" || return 77
    ci_require_canonical_active_pin APR_SHA256_URL "$APR_SHA256_URL" "$CI_ACTIVE_PIN_APR_SHA256_URL" || return 77
    ci_require_canonical_active_pin APR_UTIL_VERSION "$APR_UTIL_VERSION" "$CI_ACTIVE_PIN_APR_UTIL_VERSION" || return 77
    ci_require_canonical_active_pin APR_UTIL_ARCHIVE_NAME "$APR_UTIL_ARCHIVE_NAME" "$CI_ACTIVE_PIN_APR_UTIL_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin APR_UTIL_SOURCE_URL "$APR_UTIL_SOURCE_URL" "$CI_ACTIVE_PIN_APR_UTIL_SOURCE_URL" || return 77
    ci_require_canonical_active_pin APR_UTIL_SHA256 "$APR_UTIL_SHA256" "$CI_ACTIVE_PIN_APR_UTIL_SHA256" || return 77
    ci_require_canonical_active_pin APR_UTIL_SHA256_URL "$APR_UTIL_SHA256_URL" "$CI_ACTIVE_PIN_APR_UTIL_SHA256_URL" || return 77
    ci_require_canonical_active_pin PCRE2_VERSION "$PCRE2_VERSION" "$CI_ACTIVE_PIN_PCRE2_VERSION" || return 77
    ci_require_canonical_active_pin PCRE2_ARCHIVE_NAME "$PCRE2_ARCHIVE_NAME" "$CI_ACTIVE_PIN_PCRE2_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin PCRE2_SOURCE_URL "$PCRE2_SOURCE_URL" "$CI_ACTIVE_PIN_PCRE2_SOURCE_URL" || return 77
    ci_require_canonical_active_pin PCRE2_SHA256 "$PCRE2_SHA256" "$CI_ACTIVE_PIN_PCRE2_SHA256" || return 77
    ci_require_canonical_active_pin PCRE2_SHA256_URL "$PCRE2_SHA256_URL" "$CI_ACTIVE_PIN_PCRE2_SHA256_URL" || return 77
    ci_require_canonical_active_pin NGINX_SOURCE_MODE "$NGINX_SOURCE_MODE" "$CI_ACTIVE_PIN_NGINX_SOURCE_MODE" || return 77
    ci_require_canonical_active_pin NGINX_SOURCE_REPO_URL "$NGINX_SOURCE_REPO_URL" "$CI_ACTIVE_PIN_NGINX_SOURCE_REPO_URL" || return 77
    ci_require_canonical_active_pin NGINX_GITHUB_REPO "$NGINX_GITHUB_REPO" "$CI_ACTIVE_PIN_NGINX_GITHUB_REPO" || return 77
    ci_require_canonical_active_pin NGINX_RELEASE_TAG "$NGINX_RELEASE_TAG" "$CI_ACTIVE_PIN_NGINX_RELEASE_TAG" || return 77
    ci_require_canonical_active_pin NGINX_SOURCE_GIT_REF "$NGINX_SOURCE_GIT_REF" "$CI_ACTIVE_PIN_NGINX_SOURCE_GIT_REF" || return 77
    ci_require_canonical_active_pin NGINX_RELEASE_ASSET_NAME "$NGINX_RELEASE_ASSET_NAME" "$CI_ACTIVE_PIN_NGINX_RELEASE_ASSET_NAME" || return 77
    ci_require_canonical_active_pin NGINX_DOWNLOAD_URL "$NGINX_DOWNLOAD_URL" "$CI_ACTIVE_PIN_NGINX_DOWNLOAD_URL" || return 77
    ci_require_canonical_active_pin NGINX_SHA256 "$NGINX_SHA256" "$CI_ACTIVE_PIN_NGINX_SHA256" || return 77
    ci_require_canonical_active_pin NGINX_QUIC_TLS_LIBRARY "$NGINX_QUIC_TLS_LIBRARY" "$CI_ACTIVE_PIN_NGINX_QUIC_TLS_LIBRARY" || return 77
    ci_require_canonical_active_pin NGINX_QUIC_TLS_VERSION "$NGINX_QUIC_TLS_VERSION" "$CI_ACTIVE_PIN_NGINX_QUIC_TLS_VERSION" || return 77
    ci_require_canonical_active_pin NGINX_QUIC_TLS_ARCHIVE_NAME "$NGINX_QUIC_TLS_ARCHIVE_NAME" "$CI_ACTIVE_PIN_NGINX_QUIC_TLS_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin NGINX_QUIC_TLS_SOURCE_URL "$NGINX_QUIC_TLS_SOURCE_URL" "$CI_ACTIVE_PIN_NGINX_QUIC_TLS_SOURCE_URL" || return 77
    ci_require_canonical_active_pin NGINX_QUIC_TLS_SOURCE_SHA256 "$NGINX_QUIC_TLS_SOURCE_SHA256" "$CI_ACTIVE_PIN_NGINX_QUIC_TLS_SOURCE_SHA256" || return 77
    ci_require_canonical_active_pin HAPROXY_VERSION "$HAPROXY_VERSION" "$CI_ACTIVE_PIN_HAPROXY_VERSION" || return 77
    ci_require_canonical_active_pin HAPROXY_SERIES "$HAPROXY_SERIES" "$CI_ACTIVE_PIN_HAPROXY_SERIES" || return 77
    ci_require_canonical_active_pin HAPROXY_RELEASE_ROOT_URL "$HAPROXY_RELEASE_ROOT_URL" "$CI_ACTIVE_PIN_HAPROXY_RELEASE_ROOT_URL" || return 77
    ci_require_canonical_active_pin HAPROXY_SERIES_BASE_URL "$HAPROXY_SERIES_BASE_URL" "$CI_ACTIVE_PIN_HAPROXY_SERIES_BASE_URL" || return 77
    ci_require_canonical_active_pin HAPROXY_ARCHIVE_NAME "$HAPROXY_ARCHIVE_NAME" "$CI_ACTIVE_PIN_HAPROXY_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin HAPROXY_SOURCE_URL "$HAPROXY_SOURCE_URL" "$CI_ACTIVE_PIN_HAPROXY_SOURCE_URL" || return 77
    ci_require_canonical_active_pin HAPROXY_SHA256_URL "$HAPROXY_SHA256_URL" "$CI_ACTIVE_PIN_HAPROXY_SHA256_URL" || return 77
    ci_require_canonical_active_pin HAPROXY_SHA256 "$HAPROXY_SHA256" "$CI_ACTIVE_PIN_HAPROXY_SHA256" || return 77
    ci_require_canonical_active_pin HAPROXY_HTX_VERSION "$HAPROXY_HTX_VERSION" "$CI_ACTIVE_PIN_HAPROXY_HTX_VERSION" || return 77
    ci_require_canonical_active_pin HAPROXY_HTX_SERIES "$HAPROXY_HTX_SERIES" "$CI_ACTIVE_PIN_HAPROXY_HTX_SERIES" || return 77
    ci_require_canonical_active_pin HAPROXY_HTX_SERIES_BASE_URL "$HAPROXY_HTX_SERIES_BASE_URL" "$CI_ACTIVE_PIN_HAPROXY_HTX_SERIES_BASE_URL" || return 77
    ci_require_canonical_active_pin HAPROXY_HTX_ARCHIVE_NAME "$HAPROXY_HTX_ARCHIVE_NAME" "$CI_ACTIVE_PIN_HAPROXY_HTX_ARCHIVE_NAME" || return 77
    ci_require_canonical_active_pin HAPROXY_HTX_SOURCE_URL "$HAPROXY_HTX_SOURCE_URL" "$CI_ACTIVE_PIN_HAPROXY_HTX_SOURCE_URL" || return 77
    ci_require_canonical_active_pin HAPROXY_HTX_SHA256 "$HAPROXY_HTX_SHA256" "$CI_ACTIVE_PIN_HAPROXY_HTX_SHA256" || return 77
    return 0
}

ci_validate_https_runtime_url_config() {
    ci_require_canonical_active_upstream_pins || return 77
    ci_validate_safe_ref_config || return 77
    ci_validate_global_maintenance_pin_config || return 77
    ci_require_https_github_repo_url "$CRS_REPO_URL" CRS_REPO_URL || return 77
    ci_require_https_github_repo_url "$MODSECURITY_REPO_URL" MODSECURITY_REPO_URL || return 77
    ci_require_https_github_repo_url "$MODSECURITY_V3_GIT_URL" MODSECURITY_V3_GIT_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_APACHE_REPO_URL" MODSECURITY_APACHE_REPO_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_APACHE_GIT_URL" MODSECURITY_APACHE_GIT_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_NGINX_REPO_URL" MODSECURITY_NGINX_REPO_URL || return 77
    ci_require_https_github_repo_url_if_set "$MODSECURITY_NGINX_GIT_URL" MODSECURITY_NGINX_GIT_URL || return 77
    ci_require_https_github_repo_url "$NGINX_SOURCE_REPO_URL" NGINX_SOURCE_REPO_URL || return 77
    ci_require_https_github_repo_url "$NGINX_GITHUB_REPO" NGINX_GITHUB_REPO || return 77
    ci_require_https_url "$NGINX_DOWNLOAD_URL" NGINX_DOWNLOAD_URL || return 77
    ci_require_https_url "$NGINX_QUIC_TLS_SOURCE_URL" NGINX_QUIC_TLS_SOURCE_URL || return 77
    ci_require_https_github_repo_url "$GO_FTW_SOURCE_URL" GO_FTW_SOURCE_URL || return 77
    ci_require_https_github_repo_url "$ALBEDO_SOURCE_URL" ALBEDO_SOURCE_URL || return 77
    ci_require_https_github_repo_url "$EXPAT_SOURCE_URL" EXPAT_SOURCE_URL || return 77
    ci_require_https_url "$ENVOY_SOURCE_URL" ENVOY_SOURCE_URL || return 77
    ci_require_https_url "$ENVOY_INSTALL_DOCS_URL" ENVOY_INSTALL_DOCS_URL || return 77
    ci_require_https_url_if_set "$ENVOY_DOWNLOAD_URL" ENVOY_DOWNLOAD_URL || return 77
    ci_require_https_url_if_set "$ENVOY_SHA256_URL" ENVOY_SHA256_URL || return 77
    ci_require_traefik_pinned_provenance || return 77
    ci_require_https_url "$LIGHTTPD_SOURCE_URL" LIGHTTPD_SOURCE_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_RELEASE_INDEX_URL" LIGHTTPD_RELEASE_INDEX_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_LATEST_URL" LIGHTTPD_LATEST_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_DOWNLOAD_URL" LIGHTTPD_DOWNLOAD_URL || return 77
    ci_require_https_url_if_set "$LIGHTTPD_SHA256_URL" LIGHTTPD_SHA256_URL || return 77
    ci_require_https_url "$HAPROXY_SOURCE_URL" HAPROXY_SOURCE_URL || return 77
    ci_require_https_url "$HTTPD_SOURCE_URL" HTTPD_SOURCE_URL || return 77
    ci_require_https_url "$APR_SOURCE_URL" APR_SOURCE_URL || return 77
    ci_require_apr_util_pinned_provenance || return 77
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

ci_find_bin_list() {
    ci_candidate_list=$1
    while [ -n "$ci_candidate_list" ]; do
        ci_candidate_list=${ci_candidate_list#"${ci_candidate_list%%[![:space:]]*}"}
        [ -n "$ci_candidate_list" ] || break
        ci_candidate=${ci_candidate_list%%[[:space:]]*}
        if [ "$ci_candidate" = "$ci_candidate_list" ]; then
            ci_candidate_list=
        else
            ci_candidate_list=${ci_candidate_list#"$ci_candidate"}
        fi
        if ci_find_bin_multi "$ci_candidate"; then
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
    return 77
}

is_local_run() {
    [ "${GITHUB_ACTIONS:-}" = "true" ] && return 1
    [ "${CI:-}" = "true" ] && return 1
    return 0
}

ci_fail_local_provisioning() {
    echo "FAIL: $*" >&2
    return 1
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
    if [ -e "$ci_runtime_destination" ] || [ -L "$ci_runtime_destination" ]; then
        ci_blocked "${ci_runtime_name} staging destination already exists or is a symlink"
        return 77
    fi
    ci_runtime_stage=$(mktemp "${ci_runtime_destination}.tmp.XXXXXX") || return 1
    if ! cp "$ci_runtime_system_path" "$ci_runtime_stage"; then
        rm -f "$ci_runtime_stage"
        return 1
    fi
    chmod 0755 "$ci_runtime_stage" || {
        rm -f "$ci_runtime_stage"
        return 1
    }
    if ! mv "$ci_runtime_stage" "$ci_runtime_destination"; then
        rm -f "$ci_runtime_stage"
        return 1
    fi
    printf '%s\n' "$ci_runtime_destination"
}

envoy_build_paths() {
    export ENVOY_COMPONENT_ROOT ENVOY_SOURCE_ROOT ENVOY_BUILD_ROOT ENVOY_BIN
    printf 'ENVOY_COMPONENT_ROOT=%s\n' "$ENVOY_COMPONENT_ROOT"
    printf 'ENVOY_SOURCE_ROOT=%s\n' "$ENVOY_SOURCE_ROOT"
    printf 'ENVOY_BUILD_ROOT=%s\n' "$ENVOY_BUILD_ROOT"
    printf 'ENVOY_BIN=%s\n' "$ENVOY_BIN"
    return $?
}

traefik_build_paths() {
    export TRAEFIK_COMPONENT_ROOT TRAEFIK_SOURCE_ROOT TRAEFIK_BUILD_ROOT TRAEFIK_BIN TRAEFIK_ARCHIVE
    printf 'TRAEFIK_COMPONENT_ROOT=%s\n' "$TRAEFIK_COMPONENT_ROOT"
    printf 'TRAEFIK_SOURCE_ROOT=%s\n' "$TRAEFIK_SOURCE_ROOT"
    printf 'TRAEFIK_BUILD_ROOT=%s\n' "$TRAEFIK_BUILD_ROOT"
    printf 'TRAEFIK_BIN=%s\n' "$TRAEFIK_BIN"
    printf 'TRAEFIK_ARCHIVE=%s\n' "$TRAEFIK_ARCHIVE"
    return $?
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
    return $?
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
    if [ "${ALLOW_RUNTIME_DOWNLOADS:-0}" != "1" ]; then
        echo "FAIL: Envoy provisioning requires ALLOW_RUNTIME_DOWNLOADS=1" >&2
        return 1
    fi
    if ALLOW_RUNTIME_DOWNLOADS="${ALLOW_RUNTIME_DOWNLOADS:-0}" FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-envoy-runtime.sh" >&2 \
        && ci_runtime_binary_matches_version "$ENVOY_BIN" "$ENVOY_VERSION" --version; then
        printf '%s\n' "$ENVOY_BIN"
        return 0
    fi
    echo "FAIL: Envoy provisioning did not produce $ENVOY_BIN" >&2
    return 1
}

require_or_provision_traefik() {
    ci_require_traefik_pinned_provenance || return 77
    traefik_build_paths >/dev/null
    if ALLOW_RUNTIME_DOWNLOADS="${ALLOW_RUNTIME_DOWNLOADS:-0}" FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" \
        sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-traefik-runtime.sh" >&2; then
        if ci_runtime_binary_matches_version "$TRAEFIK_BIN" "$TRAEFIK_VERSION" version; then
            printf '%s\n' "$TRAEFIK_BIN"
            return 0
        fi
    else
        ci_traefik_prepare_status=$?
        if [ "$ci_traefik_prepare_status" -eq 77 ]; then
            return 77
        fi
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
        ci_staged_runtime=$(ci_stage_matching_runtime_binary lighttpd "$LIGHTTPD_VERSION" -v "$LIGHTTPD_CONNECTOR_BUILD_ROOT/bin/lighttpd" 2>/dev/null || true)
        if [ -n "$ci_staged_runtime" ]; then
            LIGHTTPD_BIN=$ci_staged_runtime
            export LIGHTTPD_BIN
        fi
    fi
    if [ -x "$LIGHTTPD_BIN" ] && [ -f "$LIGHTTPD_INCLUDE_DIR/plugin.h" ]; then
        printf '%s\n' "$LIGHTTPD_BIN"
        return 0
    fi
    if [ "${ALLOW_RUNTIME_DOWNLOADS:-0}" != "1" ] || [ "${ALLOW_RUNTIME_BUILDS:-0}" != "1" ]; then
        echo "FAIL: lighttpd provisioning requires ALLOW_RUNTIME_DOWNLOADS=1 and ALLOW_RUNTIME_BUILDS=1" >&2
        return 1
    fi
    if ALLOW_RUNTIME_DOWNLOADS="$ALLOW_RUNTIME_DOWNLOADS" ALLOW_RUNTIME_BUILDS="$ALLOW_RUNTIME_BUILDS" \
        LIGHTTPD_BIN='' \
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

    if ! ci_command_path "$ci_required_cmd" >/dev/null 2>&1; then
        skip_blocked "$ci_required_reason"
        return $?
    fi
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

    ci_apxs_path=$(ci_find_bin_list "$CI_APXS_BIN_CANDIDATES" 2>/dev/null || true)
    if framework_apxs_has_usable_headers "$ci_apxs_path"; then
        printf '%s\n' "$ci_apxs_path"
        return 0
    fi

    # Do not probe a cache or build-root candidate automatically.  Checking an
    # APXS candidate requires executing it with `-q INCLUDEDIR`; an attacker
    # who can pre-populate a shared cache could otherwise run code before the
    # runtime-provisioning provenance checks are reached.  A caller may use a
    # reviewed APXS explicitly through APXS_BIN/APXS, or the trusted PATH
    # discovery above can select a host-installed APXS.

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
        return $?
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
    return $?
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
        return $?
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
    return $?
}

require_modsecurity_headers_or_blocked() {
    modsecurity_include_flags_or_blocked >/dev/null || return $?
    return 0
}

require_or_provision_modsecurity_headers() {
    modsecurity_include_flags_or_provision >/dev/null || return $?
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
        return $?
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
    return $?
}

require_nginx_headers_or_blocked() {
    nginx_include_flags_or_blocked >/dev/null || return $?
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
        ci_haproxy_parent=$(CDPATH='' cd -- "$ci_haproxy_dir/.." 2>/dev/null && pwd)
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
        return $?
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
    return $?
}

require_haproxy_headers_or_blocked() {
    haproxy_include_flags_or_blocked >/dev/null || return $?
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
            *) : ;;
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

assert_runtime_path_under_root() {
    ci_contained_path=$1
    ci_containment_root=$2
    ci_containment_label=${3:-runtime path}

    ci_require_absolute_path "$ci_contained_path" "$ci_containment_label" || return 77
    ci_require_absolute_path "$ci_containment_root" "$ci_containment_label root" || return 77
    ci_reject_traversal_path "$ci_contained_path" "$ci_containment_label" || return 77
    ci_reject_traversal_path "$ci_containment_root" "$ci_containment_label root" || return 77
    ci_contained_canonical=$(ci_canonical_path "$ci_contained_path") || return 77
    ci_root_canonical=$(ci_canonical_path "$ci_containment_root") || return 77
    case "$ci_contained_canonical" in
        "$ci_root_canonical"|"$ci_root_canonical"/*) return 0 ;;
        *)
            ci_blocked "$ci_containment_label must stay under $ci_root_canonical: $ci_contained_canonical"
            return 77
            ;;
    esac
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

# A caller can launch its own shell with dynamic-loader state, but the V3
# boundary must not forward that state to any process it starts. This helper is
# shell-only so it runs before host Git, mkdir, stat, or another executable.
ci_modsecurity_v3_scrub_dynamic_loader_environment() {
    unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_PROFILE LD_DEBUG LD_DEBUG_OUTPUT
    unset LD_BIND_NOT LD_ASSUME_KERNEL LD_ORIGIN_PATH LD_DYNAMIC_WEAK LD_HWCAP_MASK
    unset LD_SHOW_AUXV LD_TRACE_LOADED_OBJECTS LD_USE_LOAD_BIAS
    unset LD_PREFER_MAP_32BIT_EXEC LD_POINTER_GUARD
}

# Bind every V3 provenance command to the reviewed system Git rather than
# selecting an executable from caller PATH.
ci_modsecurity_v3_require_host_git() {
    ci_v3_host_git_bin=/usr/bin/git
    if [ -L "$ci_v3_host_git_bin" ] || [ ! -f "$ci_v3_host_git_bin" ] || [ ! -x "$ci_v3_host_git_bin" ]; then
        ci_blocked "ModSecurity v3 host Git must be a non-symlinked regular executable: $ci_v3_host_git_bin"
        return 77
    fi
    ci_v3_host_git_metadata=$(/usr/bin/stat -c '%u %a' "$ci_v3_host_git_bin" 2>/dev/null) || {
        ci_blocked "ModSecurity v3 host Git metadata could not be inspected: $ci_v3_host_git_bin"
        return 77
    }
    ci_v3_host_git_owner=${ci_v3_host_git_metadata%% *}
    ci_v3_host_git_mode=${ci_v3_host_git_metadata#* }
    case "$ci_v3_host_git_mode" in
        ''|*[!0-7]*)
            ci_blocked "ModSecurity v3 host Git mode is invalid: $ci_v3_host_git_bin"
            return 77
            ;;
    esac
    if [ "$ci_v3_host_git_owner" != "0" ]; then
        ci_blocked "ModSecurity v3 host Git must be root-owned: $ci_v3_host_git_bin"
        return 77
    fi
    if [ "$((0$ci_v3_host_git_mode & 022))" -ne 0 ]; then
        ci_blocked "ModSecurity v3 host Git must not be group- or world-writable: $ci_v3_host_git_bin"
        return 77
    fi
    return 0
}

# Run Git for the ModSecurity v3 provenance boundary without inheriting
# caller-controlled repository, hook, transport, credential, or executable
# search-path settings.
ci_modsecurity_v3_git() (
    ci_modsecurity_v3_scrub_dynamic_loader_environment
    ci_modsecurity_v3_require_host_git || return 77
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
    PATH=/usr/bin:/bin \
        "$ci_v3_host_git_bin" --no-optional-locks \
            -c core.hooksPath=/dev/null \
            -c core.fsmonitor=false \
            -c core.useBuiltinFSMonitor=false \
            -c status.showUntrackedFiles=all \
            -c protocol.file.allow=never \
            -c fetch.recurseSubmodules=false -c submodule.recurse=false \
            -c http.sslVerify=true "$@"
    return $?
)

# Every post-init operation runs from the validated physical root and overrides
# core.worktree on the Git command itself. Git's --git-dir/--work-tree flags
# and inherited GIT_DIR/GIT_WORK_TREE can leave git-submodule without a usable
# worktree; changing to the canonical root keeps that helper contained while
# the host runner still clears all caller-controlled Git environment state.
ci_modsecurity_v3_fresh_root_git() {
    ci_v3_fresh_root=$1
    shift
    ci_require_absolute_path "$ci_v3_fresh_root" "ModSecurity v3 fresh root" || return 77
    if [ ! -d "$ci_v3_fresh_root" ] || [ -L "$ci_v3_fresh_root" ]; then
        ci_blocked "ModSecurity v3 fresh root must be a non-symlinked directory: $ci_v3_fresh_root"
        return 77
    fi
    ci_v3_fresh_root_real=$(ci_canonical_existing "$ci_v3_fresh_root") || {
        ci_blocked "ModSecurity v3 fresh root could not be canonicalized: $ci_v3_fresh_root"
        return 77
    }
    if [ "$ci_v3_fresh_root" != "$ci_v3_fresh_root_real" ]; then
        ci_blocked "ModSecurity v3 fresh root must be canonical: $ci_v3_fresh_root"
        return 77
    fi
    if [ ! -d "$ci_v3_fresh_root/.git" ] || [ -L "$ci_v3_fresh_root/.git" ]; then
        ci_blocked "ModSecurity v3 fresh root Gitdir must be a non-symlinked directory: $ci_v3_fresh_root/.git"
        return 77
    fi
    (
        cd -- "$ci_v3_fresh_root" || {
            ci_blocked "ModSecurity v3 fresh root could not be entered: $ci_v3_fresh_root"
            return 77
        }
        ci_modsecurity_v3_git \
            "--work-tree=$ci_v3_fresh_root" \
            -c core.worktree="$ci_v3_fresh_root" \
            -c core.attributesfile=/dev/null \
            -c core.sparseCheckout=false \
            "$@"
    )
}

ci_modsecurity_v3_clear_fresh_local_config_key() {
    ci_v3_config_root=$1
    ci_v3_config_key=$2

    ci_v3_unset_rc=0
    ci_modsecurity_v3_fresh_root_git "$ci_v3_config_root" config --local --unset-all "$ci_v3_config_key" >/dev/null 2>&1 || ci_v3_unset_rc=$?
    case "$ci_v3_unset_rc" in
        0|5) ;;
        *)
            ci_blocked "ModSecurity v3 could not clear local $ci_v3_config_key configuration"
            return 77
            ;;
    esac

    ci_v3_local_values_rc=0
    ci_v3_local_values=$(ci_modsecurity_v3_fresh_root_git "$ci_v3_config_root" config --local --get-all "$ci_v3_config_key" 2>/dev/null) || ci_v3_local_values_rc=$?
    case "$ci_v3_local_values_rc" in
        1) return 0 ;;
        0)
            ci_blocked "ModSecurity v3 local $ci_v3_config_key configuration remains set"
            return 77
            ;;
        *)
            ci_blocked "ModSecurity v3 local $ci_v3_config_key configuration could not be inspected"
            return 77
            ;;
    esac
}

# Remove every local configuration value that can redirect fresh checkout bytes,
# select external attributes, retain sparse state, or execute a custom recursive
# submodule update. This must run immediately before recursive Git processing.
ci_modsecurity_v3_scrub_fresh_recursive_config() {
    ci_v3_scrub_root=$1
    for ci_v3_scrub_key in core.worktree core.attributesfile core.sparseCheckout; do
        ci_modsecurity_v3_clear_fresh_local_config_key "$ci_v3_scrub_root" "$ci_v3_scrub_key" || return 77
    done

    ci_v3_submodule_update_keys=$(ci_modsecurity_v3_fresh_root_git "$ci_v3_scrub_root" config --local --list --name-only 2>/dev/null) || {
        ci_blocked "ModSecurity v3 local recursive configuration could not be listed"
        return 77
    }
    ci_v3_submodule_update_keys=$(printf '%s\n' "$ci_v3_submodule_update_keys" | /usr/bin/awk 'tolower($0) ~ /^submodule\..*\.update$/')
    if [ -n "$ci_v3_submodule_update_keys" ]; then
        while IFS= read -r ci_v3_submodule_update_key; do
            [ -n "$ci_v3_submodule_update_key" ] || continue
            ci_modsecurity_v3_clear_fresh_local_config_key \
                "$ci_v3_scrub_root" "$ci_v3_submodule_update_key" || return 77
        done <<EOF
$ci_v3_submodule_update_keys
EOF
    fi
    return 0
}

ci_modsecurity_v3_create_private_fresh_root() {
    ci_v3_private_root=$1
    if [ -e "$ci_v3_private_root" ] || [ -L "$ci_v3_private_root" ]; then
        ci_blocked "ModSecurity v3 fresh source root already exists: $ci_v3_private_root"
        return 77
    fi
    (umask 077 && /usr/bin/mkdir -m 700 "$ci_v3_private_root") || {
        ci_blocked "ModSecurity v3 private source root could not be created: $ci_v3_private_root"
        return 77
    }
    if [ ! -d "$ci_v3_private_root" ] || [ -L "$ci_v3_private_root" ]; then
        ci_blocked "ModSecurity v3 private source root is not a non-symlinked directory: $ci_v3_private_root"
        return 77
    fi
    ci_v3_private_metadata=$(/usr/bin/stat -c '%u %a' "$ci_v3_private_root" 2>/dev/null) || {
        ci_blocked "ModSecurity v3 private source root metadata could not be inspected: $ci_v3_private_root"
        return 77
    }
    ci_v3_private_owner=${ci_v3_private_metadata%% *}
    ci_v3_private_mode=${ci_v3_private_metadata#* }
    ci_v3_current_uid=$(/usr/bin/id -u 2>/dev/null || true)
    case "$ci_v3_private_mode" in
        ''|*[!0-7]*)
            ci_blocked "ModSecurity v3 private source root mode is invalid: $ci_v3_private_root"
            return 77
            ;;
    esac
    if [ -z "$ci_v3_current_uid" ] || [ "$ci_v3_private_owner" != "$ci_v3_current_uid" ]; then
        ci_blocked "ModSecurity v3 private source root must be owned by the current user: $ci_v3_private_root"
        return 77
    fi
    if [ "$((0$ci_v3_private_mode & 077))" -ne 0 ]; then
        ci_blocked "ModSecurity v3 private source root must not grant group or other access: $ci_v3_private_root"
        return 77
    fi
    return 0
}

# A public caller may select the storage parent, but not a symlinked or
# non-canonical parent path. Bind the non-existing destination to the physical
# parent before mkdir so a parent symlink cannot receive fresh checkout bytes.
ci_modsecurity_v3_require_fresh_destination() {
    ci_v3_destination=$1
    ci_require_absolute_path "$ci_v3_destination" "ModSecurity v3 provisioning destination" || return 77
    ci_reject_traversal_path "$ci_v3_destination" "ModSecurity v3 provisioning destination" || return 77
    if [ -e "$ci_v3_destination" ] || [ -L "$ci_v3_destination" ]; then
        ci_blocked "ModSecurity v3 fresh source root already exists: $ci_v3_destination"
        return 77
    fi
    ci_v3_destination_parent=${ci_v3_destination%/*}
    ci_v3_destination_leaf=${ci_v3_destination##*/}
    if [ -z "$ci_v3_destination_parent" ]; then
        ci_v3_destination_parent=/
    fi
    case "$ci_v3_destination_leaf" in
        ''|.|..)
            ci_blocked "ModSecurity v3 provisioning destination must name a child directory: $ci_v3_destination"
            return 77
            ;;
    esac
    if [ ! -d "$ci_v3_destination_parent" ] || [ -L "$ci_v3_destination_parent" ]; then
        ci_blocked "ModSecurity v3 provisioning parent must be an existing non-symlinked directory: $ci_v3_destination_parent"
        return 77
    fi
    ci_v3_destination_parent_real=$(ci_canonical_existing "$ci_v3_destination_parent") || {
        ci_blocked "ModSecurity v3 provisioning parent could not be canonicalized: $ci_v3_destination_parent"
        return 77
    }
    if [ "$ci_v3_destination_parent" != "$ci_v3_destination_parent_real" ]; then
        ci_blocked "ModSecurity v3 provisioning parent must be canonical: $ci_v3_destination_parent"
        return 77
    fi
    if [ "$ci_v3_destination_parent_real" = / ]; then
        ci_v3_destination_expected=/$ci_v3_destination_leaf
    else
        ci_v3_destination_expected=$ci_v3_destination_parent_real/$ci_v3_destination_leaf
    fi
    if [ "$ci_v3_destination" != "$ci_v3_destination_expected" ]; then
        ci_blocked "ModSecurity v3 provisioning destination escapes its canonical parent: $ci_v3_destination"
        return 77
    fi
    return 0
}

ci_require_approved_modsecurity_v3_provenance() {
    ci_require_inherited_canonical_upstream_pins || return 77
    ci_modsecurity_v3_scrub_dynamic_loader_environment
    ci_require_https_github_repo_url "$MODSECURITY_V3_APPROVED_REPO_URL" "MODSECURITY_V3_APPROVED_REPO_URL" || return 77
    ci_require_full_git_commit "$MODSECURITY_V3_APPROVED_COMMIT" "MODSECURITY_V3_APPROVED_COMMIT" || return 77
    if [ "$MODSECURITY_REPO_URL" != "$MODSECURITY_V3_APPROVED_REPO_URL" ]; then
        ci_blocked "MODSECURITY_REPO_URL override is not permitted for ModSecurity v3: $MODSECURITY_REPO_URL"
        return 77
    fi
    if [ "$MODSECURITY_V3_GIT_URL" != "$MODSECURITY_V3_APPROVED_REPO_URL" ]; then
        ci_blocked "MODSECURITY_V3_GIT_URL override is not permitted: $MODSECURITY_V3_GIT_URL"
        return 77
    fi
    if [ "$MODSECURITY_GIT_REF" != "$MODSECURITY_V3_RELEASE_TAG" ]; then
        ci_blocked "MODSECURITY_GIT_REF is release metadata and cannot select a Git object: $MODSECURITY_GIT_REF"
        return 77
    fi
    if [ "$MODSECURITY_V3_GIT_REF" != "$MODSECURITY_V3_RELEASE_TAG" ]; then
        ci_blocked "MODSECURITY_V3_GIT_REF is release metadata and cannot select a Git object: $MODSECURITY_V3_GIT_REF"
        return 77
    fi
    return 0
}

# The approved ModSecurity v3 root at MODSECURITY_V3_APPROVED_COMMIT contains
# this exact recursive Gitlink graph.  The values are intentionally static:
# accepting a URL, path, or commit supplied by a checkout would turn the
# provenance check into a generic recursive-submodule policy.
ci_modsecurity_v3_root_gitlinks() {
    printf '%s\n' \
        'bindings/python|bc625d5bb0bac6a64bcce8dc9902208612399348' \
        'others/libinjection|211782219663f889f471650150df12b623c5766e' \
        'others/mbedtls|0fe989b6b514192783c469039edd325fd0989806' \
        'test/test-cases/secrules-language-tests|a3d4405e5a2c90488c387e589c5534974575e35b'
}

ci_modsecurity_v3_mbedtls_gitlinks() {
    printf '%s\n' \
        'framework|dff9da04438d712f7647fd995bc90fadd0c0e2ce' \
        'tf-psa-crypto|29160dd877d29658279fd683b2ae57b320ddcf09'
}

ci_modsecurity_v3_tf_psa_crypto_gitlinks() {
    printf '%s\n' \
        'drivers/pqcp/mldsa-native|5772b4f4a0105694b1203abb582273f78fa951b7' \
        'framework|dff9da04438d712f7647fd995bc90fadd0c0e2ce'
}

ci_modsecurity_v3_require_clean_checkout() {
    ci_v3_clean_dir=$1
    ci_v3_clean_label=$2

    ci_v3_status=$(ci_modsecurity_v3_git -C "$ci_v3_clean_dir" status --porcelain=v1 --untracked-files=all --ignored=matching 2>/dev/null) || {
        ci_blocked "ModSecurity v3 $ci_v3_clean_label checkout status could not be inspected"
        return 77
    }
    if [ -n "$ci_v3_status" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_clean_label checkout must be clean"
        return 77
    fi

    ci_v3_index_flags=$(ci_modsecurity_v3_git -C "$ci_v3_clean_dir" ls-files -v 2>/dev/null) || {
        ci_blocked "ModSecurity v3 $ci_v3_clean_label checkout index flags could not be inspected"
        return 77
    }
    if ! printf '%s\n' "$ci_v3_index_flags" | /usr/bin/awk 'NF && $1 != "H" { exit 1 }'; then
        ci_blocked "ModSecurity v3 $ci_v3_clean_label checkout has non-normal Git index flags"
        return 77
    fi
    return 0
}

ci_modsecurity_v3_require_exact_gitlinks() {
    ci_v3_gitlink_dir=$1
    ci_v3_expected_gitlinks=$2
    ci_v3_gitlink_label=$3

    ci_v3_index=$(ci_modsecurity_v3_git -C "$ci_v3_gitlink_dir" ls-files --stage 2>/dev/null) || {
        ci_blocked "ModSecurity v3 $ci_v3_gitlink_label checkout index could not be inspected"
        return 77
    }
    ci_v3_actual_gitlinks=$(printf '%s\n' "$ci_v3_index" | /usr/bin/awk '$1 == "160000" { print $4 "|" $2 }')
    if [ "$ci_v3_actual_gitlinks" != "$ci_v3_expected_gitlinks" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_gitlink_label checkout Gitlink topology is not approved"
        return 77
    fi
    return 0
}

ci_modsecurity_v3_require_checkout() {
    ci_v3_dir=$1
    ci_v3_expected_worktree=$2
    ci_v3_expected_origin=$3
    ci_v3_expected_commit=$4
    ci_v3_expected_git_dir=$5
    ci_v3_expected_gitlinks=$6
    ci_v3_label=$7
    ci_v3_kind=$8
    ci_v3_root=$9

    if [ ! -d "$ci_v3_dir" ] || [ -L "$ci_v3_dir" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label worktree is missing or symlinked: $ci_v3_dir"
        return 77
    fi
    ci_v3_real_dir=$(ci_canonical_existing "$ci_v3_dir") || {
        ci_blocked "ModSecurity v3 $ci_v3_label worktree could not be canonicalized: $ci_v3_dir"
        return 77
    }
    if [ "$ci_v3_real_dir" != "$ci_v3_expected_worktree" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label worktree escapes the approved source root"
        return 77
    fi

    case "$ci_v3_kind" in
        root)
            if [ ! -d "$ci_v3_dir/.git" ] || [ -L "$ci_v3_dir/.git" ]; then
                ci_blocked "ModSecurity v3 root checkout must have a non-symlinked .git directory"
                return 77
            fi
            ;;
        child)
            if [ ! -f "$ci_v3_dir/.git" ] || [ -L "$ci_v3_dir/.git" ]; then
                ci_blocked "ModSecurity v3 $ci_v3_label child must have a non-symlinked Gitdir file"
                return 77
            fi
            ;;
        *)
            ci_blocked "ModSecurity v3 internal checkout-kind error: $ci_v3_kind"
            return 77
            ;;
    esac

    ci_v3_top=$(ci_modsecurity_v3_git -C "$ci_v3_dir" rev-parse --show-toplevel 2>/dev/null) || {
        ci_blocked "ModSecurity v3 $ci_v3_label worktree could not be resolved"
        return 77
    }
    if [ "$ci_v3_top" != "$ci_v3_expected_worktree" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label Git worktree differs from its physical checkout"
        return 77
    fi

    ci_v3_git_dir=$(ci_modsecurity_v3_git -C "$ci_v3_dir" rev-parse --absolute-git-dir 2>/dev/null) || {
        ci_blocked "ModSecurity v3 $ci_v3_label Gitdir could not be resolved"
        return 77
    }
    ci_v3_git_dir_real=$(ci_canonical_existing "$ci_v3_git_dir") || {
        ci_blocked "ModSecurity v3 $ci_v3_label Gitdir does not exist"
        return 77
    }
    ci_v3_expected_git_dir_real=$(ci_canonical_existing "$ci_v3_expected_git_dir") || {
        ci_blocked "ModSecurity v3 $ci_v3_label expected Gitdir does not exist"
        return 77
    }
    if [ "$ci_v3_git_dir_real" != "$ci_v3_expected_git_dir_real" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label Gitdir is not the approved contained Gitdir"
        return 77
    fi
    case "$ci_v3_git_dir_real" in
        "$ci_v3_root/.git"|"$ci_v3_root/.git/modules/"*) ;;
        *)
            ci_blocked "ModSecurity v3 $ci_v3_label Gitdir escapes the approved root"
            return 77
            ;;
    esac

    ci_v3_remotes=$(ci_modsecurity_v3_git -C "$ci_v3_dir" remote 2>/dev/null) || {
        ci_blocked "ModSecurity v3 $ci_v3_label remotes could not be inspected"
        return 77
    }
    if [ "$ci_v3_remotes" != "origin" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label checkout must have exactly one origin remote"
        return 77
    fi
    ci_v3_origin=$(ci_modsecurity_v3_git -C "$ci_v3_dir" config --get remote.origin.url 2>/dev/null || true)
    if [ "$ci_v3_origin" != "$ci_v3_expected_origin" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label checkout has unexpected origin: $ci_v3_origin"
        return 77
    fi

    ci_v3_symbolic_head=$(ci_modsecurity_v3_git -C "$ci_v3_dir" symbolic-ref -q HEAD 2>/dev/null || true)
    if [ -n "$ci_v3_symbolic_head" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label checkout must use a detached HEAD"
        return 77
    fi
    ci_v3_head=$(ci_modsecurity_v3_git -C "$ci_v3_dir" rev-parse --verify "HEAD^{commit}" 2>/dev/null || true)
    if [ "$ci_v3_head" != "$ci_v3_expected_commit" ]; then
        ci_blocked "ModSecurity v3 $ci_v3_label checked-out commit does not match the approved commit"
        return 77
    fi

    if ! ci_modsecurity_v3_git -C "$ci_v3_dir" fsck --full --no-dangling >/dev/null 2>&1; then
        ci_blocked "ModSecurity v3 $ci_v3_label Git object verification failed"
        return 77
    fi
    ci_modsecurity_v3_require_clean_checkout "$ci_v3_dir" "$ci_v3_label" || return 77
    ci_modsecurity_v3_require_exact_gitlinks "$ci_v3_dir" "$ci_v3_expected_gitlinks" "$ci_v3_label" || return 77
    return 0
}

ci_require_approved_modsecurity_v3_root_checkout() {
    ci_v3_checkout=${1:-$MODSECURITY_V3_SOURCE_DIR}
    ci_require_approved_modsecurity_v3_provenance || return 77
    ci_require_absolute_path "$ci_v3_checkout" "MODSECURITY_V3_SOURCE_DIR" || return 77
    if [ ! -d "$ci_v3_checkout" ] || [ -L "$ci_v3_checkout" ]; then
        ci_blocked "ModSecurity v3 source must be a non-symlinked Git checkout: $ci_v3_checkout"
        return 77
    fi
    ci_v3_root=$(ci_canonical_existing "$ci_v3_checkout") || {
        ci_blocked "ModSecurity v3 source could not be canonicalized: $ci_v3_checkout"
        return 77
    }
    if [ "$ci_v3_checkout" != "$ci_v3_root" ]; then
        ci_blocked "ModSecurity v3 source path must be canonical and cannot traverse a symlink"
        return 77
    fi
    if [ ! -f "$ci_v3_root/.gitmodules" ] || [ -L "$ci_v3_root/.gitmodules" ]; then
        ci_blocked "ModSecurity v3 root must contain the approved non-symlinked .gitmodules manifest"
        return 77
    fi
    ci_v3_root_gitlinks=$(ci_modsecurity_v3_root_gitlinks)
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root" "$ci_v3_root" "$MODSECURITY_V3_APPROVED_REPO_URL" \
        "$MODSECURITY_V3_APPROVED_COMMIT" "$ci_v3_root/.git" \
        "$ci_v3_root_gitlinks" "root" root "$ci_v3_root" || return 77
    return 0
}

ci_modsecurity_v3_initialize_approved_submodules() {
    ci_v3_checkout=${1:-$MODSECURITY_V3_SOURCE_DIR}
    ci_require_approved_modsecurity_v3_root_checkout "$ci_v3_checkout" || return 77
    ci_modsecurity_v3_scrub_fresh_recursive_config "$ci_v3_checkout" || return 77
    if ! ci_modsecurity_v3_fresh_root_git "$ci_v3_checkout" submodule update --init --recursive --checkout; then
        ci_blocked "ModSecurity v3 approved recursive submodule initialization failed"
        return 77
    fi
    return 0
}

ci_require_approved_modsecurity_v3_checkout() {
    ci_v3_checkout=${1:-$MODSECURITY_V3_SOURCE_DIR}
    ci_require_approved_modsecurity_v3_root_checkout "$ci_v3_checkout" || return 77
    ci_v3_root=$(ci_canonical_existing "$ci_v3_checkout") || return 77
    ci_v3_mbedtls_gitlinks=$(ci_modsecurity_v3_mbedtls_gitlinks)
    ci_v3_tf_psa_crypto_gitlinks=$(ci_modsecurity_v3_tf_psa_crypto_gitlinks)

    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/bindings/python" "$ci_v3_root/bindings/python" \
        "https://github.com/owasp-modsecurity/ModSecurity-Python-bindings.git" \
        "bc625d5bb0bac6a64bcce8dc9902208612399348" \
        "$ci_v3_root/.git/modules/bindings/python" "" "bindings/python" child "$ci_v3_root" || return 77
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/others/libinjection" "$ci_v3_root/others/libinjection" \
        "https://github.com/libinjection/libinjection.git" \
        "211782219663f889f471650150df12b623c5766e" \
        "$ci_v3_root/.git/modules/others/libinjection" "" "others/libinjection" child "$ci_v3_root" || return 77
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/others/mbedtls" "$ci_v3_root/others/mbedtls" \
        "https://github.com/Mbed-TLS/mbedtls.git" \
        "0fe989b6b514192783c469039edd325fd0989806" \
        "$ci_v3_root/.git/modules/others/mbedtls" "$ci_v3_mbedtls_gitlinks" "others/mbedtls" child "$ci_v3_root" || return 77
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/others/mbedtls/framework" "$ci_v3_root/others/mbedtls/framework" \
        "https://github.com/Mbed-TLS/mbedtls-framework" \
        "dff9da04438d712f7647fd995bc90fadd0c0e2ce" \
        "$ci_v3_root/.git/modules/others/mbedtls/modules/framework" "" "others/mbedtls/framework" child "$ci_v3_root" || return 77
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/others/mbedtls/tf-psa-crypto" "$ci_v3_root/others/mbedtls/tf-psa-crypto" \
        "https://github.com/Mbed-TLS/TF-PSA-Crypto.git" \
        "29160dd877d29658279fd683b2ae57b320ddcf09" \
        "$ci_v3_root/.git/modules/others/mbedtls/modules/tf-psa-crypto" "$ci_v3_tf_psa_crypto_gitlinks" "others/mbedtls/tf-psa-crypto" child "$ci_v3_root" || return 77
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/others/mbedtls/tf-psa-crypto/drivers/pqcp/mldsa-native" "$ci_v3_root/others/mbedtls/tf-psa-crypto/drivers/pqcp/mldsa-native" \
        "https://github.com/Mbed-TLS/mldsa-native" \
        "5772b4f4a0105694b1203abb582273f78fa951b7" \
        "$ci_v3_root/.git/modules/others/mbedtls/modules/tf-psa-crypto/modules/mldsa-native" "" "others/mbedtls/tf-psa-crypto/drivers/pqcp/mldsa-native" child "$ci_v3_root" || return 77
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/others/mbedtls/tf-psa-crypto/framework" "$ci_v3_root/others/mbedtls/tf-psa-crypto/framework" \
        "https://github.com/Mbed-TLS/mbedtls-framework" \
        "dff9da04438d712f7647fd995bc90fadd0c0e2ce" \
        "$ci_v3_root/.git/modules/others/mbedtls/modules/tf-psa-crypto/modules/framework" "" "others/mbedtls/tf-psa-crypto/framework" child "$ci_v3_root" || return 77
    ci_modsecurity_v3_require_checkout \
        "$ci_v3_root/test/test-cases/secrules-language-tests" "$ci_v3_root/test/test-cases/secrules-language-tests" \
        "https://github.com/owasp-modsecurity/secrules-language-tests" \
        "a3d4405e5a2c90488c387e589c5534974575e35b" \
        "$ci_v3_root/.git/modules/test/test-cases/secrules-language-tests" "" "test/test-cases/secrules-language-tests" child "$ci_v3_root" || return 77
    return 0
}

# Public Framework provisioning API for Parent bridges and fetch consumers.
# Callers must provide a previously storage-authorized absolute destination and
# remove it safely on failure. This helper refuses an existing destination,
# creates a private root before Git, and never delegates to a generic clone.
ci_provision_approved_modsecurity_v3_checkout() {
    ci_modsecurity_v3_scrub_dynamic_loader_environment
    if [ "$#" -ne 1 ]; then
        ci_blocked "ModSecurity v3 provisioning requires exactly one destination"
        return 77
    fi
    ci_v3_provision_root=$1
    ci_require_approved_modsecurity_v3_provenance || return 77
    ci_modsecurity_v3_require_fresh_destination "$ci_v3_provision_root" || return 77
    ci_modsecurity_v3_create_private_fresh_root "$ci_v3_provision_root" || return 77

    if ! ci_modsecurity_v3_git init "$ci_v3_provision_root" >/dev/null 2>&1; then
        ci_blocked "ModSecurity v3 private source repository could not be initialized"
        return 77
    fi
    if ! ci_modsecurity_v3_fresh_root_git "$ci_v3_provision_root" remote add origin "$MODSECURITY_V3_APPROVED_REPO_URL"; then
        ci_blocked "ModSecurity v3 approved origin could not be set"
        return 77
    fi
    ci_v3_provision_origin=$(ci_modsecurity_v3_fresh_root_git "$ci_v3_provision_root" config --get remote.origin.url 2>/dev/null || true)
    if [ "$ci_v3_provision_origin" != "$MODSECURITY_V3_APPROVED_REPO_URL" ]; then
        ci_blocked "ModSecurity v3 fresh checkout has unexpected origin: $ci_v3_provision_origin"
        return 77
    fi

    if ! ci_modsecurity_v3_fresh_root_git "$ci_v3_provision_root" fetch --depth 1 --no-tags origin "$MODSECURITY_V3_APPROVED_COMMIT"; then
        ci_blocked "ModSecurity v3 approved commit fetch failed"
        return 77
    fi
    ci_v3_fetched_commit=$(ci_modsecurity_v3_fresh_root_git "$ci_v3_provision_root" rev-parse --verify "FETCH_HEAD^{commit}" 2>/dev/null || true)
    if [ "$ci_v3_fetched_commit" != "$MODSECURITY_V3_APPROVED_COMMIT" ]; then
        ci_blocked "ModSecurity v3 fetched commit does not match the approved commit"
        return 77
    fi
    ci_v3_resolved_commit=$(ci_modsecurity_v3_fresh_root_git "$ci_v3_provision_root" rev-parse --verify "$MODSECURITY_V3_APPROVED_COMMIT^{commit}" 2>/dev/null || true)
    if [ "$ci_v3_resolved_commit" != "$MODSECURITY_V3_APPROVED_COMMIT" ]; then
        ci_blocked "ModSecurity v3 resolved commit does not match the approved commit"
        return 77
    fi
    if ! ci_modsecurity_v3_fresh_root_git "$ci_v3_provision_root" checkout --detach "$MODSECURITY_V3_APPROVED_COMMIT" >/dev/null 2>&1; then
        ci_blocked "ModSecurity v3 approved commit checkout failed"
        return 77
    fi

    ci_modsecurity_v3_initialize_approved_submodules "$ci_v3_provision_root" || return 77
    ci_require_approved_modsecurity_v3_checkout "$ci_v3_provision_root" || return 77
    return 0
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
        *) : ;;
    esac
    case "$ci_safe_path" in
        /root|/root/*)
            ci_blocked "$ci_safe_label is under /root and is not a safe runtime path: $ci_safe_path"
            return 77
            ;;
        *) : ;;
    esac
    if [ -n "${REPO_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$REPO_ROOT"|"$REPO_ROOT"/*)
                ci_blocked "$ci_safe_label is inside a read-only/source checkout: $ci_safe_path"
                return 77
                ;;
            *) : ;;
        esac
    fi
    if [ -n "${FRAMEWORK_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$FRAMEWORK_ROOT"|"$FRAMEWORK_ROOT"/*)
                ci_blocked "$ci_safe_label is inside a read-only/source checkout: $ci_safe_path"
                return 77
                ;;
            *) : ;;
        esac
    fi
    if [ -n "${CONNECTOR_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
                ci_blocked "$ci_safe_label is inside a read-only/source checkout: $ci_safe_path"
                return 77
                ;;
            *) : ;;
        esac
    fi

    case "$ci_safe_path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*|"$TMP_ROOT"|"$TMP_ROOT"/*|"$LOG_ROOT"|"$LOG_ROOT"/*)
            return 0
            ;;
        *) : ;;
    esac
    if [ -n "$ci_verified_root" ]; then
        case "$ci_safe_path" in
            "$ci_verified_root"|"$ci_verified_root"/*) return 0 ;;
            *) : ;;
        esac
    fi
    if [ -n "${MRTS_BUILD_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$MRTS_BUILD_ROOT"|"$MRTS_BUILD_ROOT"/*) return 0 ;;
            *) : ;;
        esac
    fi
    if [ -n "${MRTS_NATIVE_ROOT:-}" ]; then
        case "$ci_safe_path" in
            "$MRTS_NATIVE_ROOT"|"$MRTS_NATIVE_ROOT"/*) return 0 ;;
            *) : ;;
        esac
    fi
    if [ -n "$ci_component_cache" ]; then
        case "$ci_safe_path" in
            "$ci_component_cache"|"$ci_component_cache"/*) return 0 ;;
            *) : ;;
        esac
    fi
    if [ -n "$ci_state_root" ]; then
        case "$ci_safe_path" in
            "$ci_state_root"|"$ci_state_root"/*) return 0 ;;
            *) : ;;
        esac
    fi
    if [ -n "$ci_cache_home" ]; then
        case "$ci_safe_path" in
            "$ci_cache_home"|"$ci_cache_home"/*) return 0 ;;
            *) : ;;
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
        *) : ;;
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
export MODSECURITY_V3_APPROVED_REPO_URL MODSECURITY_V3_APPROVED_COMMIT MODSECURITY_V3_RELEASE_TAG
export ENVOY_VERSION ENVOY_SOURCE_URL ENVOY_ARTIFACT_PLATFORM ENVOY_ASSET_NAME ENVOY_DOWNLOAD_URL ENVOY_SHA256 ENVOY_SHA256_URL
export LIGHTTPD_SERIES LIGHTTPD_RELEASE_ROOT_URL LIGHTTPD_SERIES_BASE_URL LIGHTTPD_VERSION LIGHTTPD_SOURCE_URL LIGHTTPD_ARCHIVE_NAME LIGHTTPD_DOWNLOAD_URL LIGHTTPD_SHA256 LIGHTTPD_SHA256_URL
export HTTPD_VERSION HTTPD_ARCHIVE_NAME HTTPD_SOURCE_URL HTTPD_SHA256 HTTPD_SHA256_URL APR_VERSION APR_ARCHIVE_NAME APR_SOURCE_URL APR_SHA256 APR_SHA256_URL APR_UTIL_VERSION APR_UTIL_ARCHIVE_NAME APR_UTIL_SOURCE_URL APR_UTIL_SHA256 APR_UTIL_SHA256_URL PCRE2_VERSION PCRE2_ARCHIVE_NAME PCRE2_SOURCE_URL PCRE2_SHA256 PCRE2_SHA256_URL
export NGINX_SOURCE_MODE NGINX_SOURCE_REPO_URL NGINX_GITHUB_REPO NGINX_RELEASE_TAG NGINX_SOURCE_GIT_REF NGINX_RELEASE_ASSET_NAME NGINX_DOWNLOAD_URL NGINX_SHA256 NGINX_SHA256_WAS_SET NGINX_SHA256_REQUESTED NGINX_QUIC_TLS_LIBRARY NGINX_QUIC_TLS_VERSION NGINX_QUIC_TLS_ARCHIVE_NAME NGINX_QUIC_TLS_SOURCE_URL NGINX_QUIC_TLS_SOURCE_SHA256
export HAPROXY_SERIES HAPROXY_RELEASE_ROOT_URL HAPROXY_SERIES_BASE_URL HAPROXY_VERSION HAPROXY_ARCHIVE_NAME HAPROXY_SOURCE_URL HAPROXY_SHA256_URL HAPROXY_SHA256 HAPROXY_HTX_SERIES HAPROXY_HTX_SERIES_BASE_URL HAPROXY_HTX_VERSION HAPROXY_HTX_ARCHIVE_NAME HAPROXY_HTX_SOURCE_URL HAPROXY_HTX_SHA256
export GO_FTW_SOURCE_URL GO_FTW_RELEASE_TAG GO_FTW_GIT_REF GO_FTW_PROMPT_EXPECTED_LATEST GO_FTW_APPROVED_COMMIT GO_FTW_BIN
export ALBEDO_SOURCE_URL ALBEDO_RELEASE_TAG ALBEDO_GIT_REF ALBEDO_PROMPT_EXPECTED_LATEST ALBEDO_APPROVED_COMMIT ALBEDO_BIN
export CI_CANONICAL_PYTHON_VERSION CI_CANONICAL_PYYAML_VERSION CI_CANONICAL_PYYAML_SHA256 CI_CANONICAL_PYYAML_ARTIFACT CI_CANONICAL_PYYAML_PLATFORM CI_CANONICAL_NODE_VERSION
export CI_OSV_LEGACY_BASE_SHA CI_OSV_LEGACY_BASE_VERSION
export CI_ACTION_CHECKOUT_REPOSITORY CI_ACTION_CHECKOUT_VERSION CI_ACTION_CHECKOUT_COMMIT CI_ACTION_SETUP_PYTHON_REPOSITORY CI_ACTION_SETUP_PYTHON_VERSION CI_ACTION_SETUP_PYTHON_COMMIT CI_ACTION_SETUP_NODE_REPOSITORY CI_ACTION_SETUP_NODE_VERSION CI_ACTION_SETUP_NODE_COMMIT CI_ACTION_UPLOAD_ARTIFACT_REPOSITORY CI_ACTION_UPLOAD_ARTIFACT_VERSION CI_ACTION_UPLOAD_ARTIFACT_COMMIT CI_ACTION_DOWNLOAD_ARTIFACT_REPOSITORY CI_ACTION_DOWNLOAD_ARTIFACT_VERSION CI_ACTION_DOWNLOAD_ARTIFACT_COMMIT CI_ACTION_GITHUB_SCRIPT_REPOSITORY CI_ACTION_GITHUB_SCRIPT_VERSION CI_ACTION_GITHUB_SCRIPT_COMMIT CI_ACTION_CREATE_GITHUB_APP_TOKEN_REPOSITORY CI_ACTION_CREATE_GITHUB_APP_TOKEN_VERSION CI_ACTION_CREATE_GITHUB_APP_TOKEN_COMMIT CI_ACTION_CREATE_PULL_REQUEST_REPOSITORY CI_ACTION_CREATE_PULL_REQUEST_VERSION CI_ACTION_CREATE_PULL_REQUEST_COMMIT CI_ACTION_CODEQL_REPOSITORY CI_ACTION_CODEQL_VERSION CI_ACTION_CODEQL_COMMIT CI_ACTION_DEPENDENCY_REVIEW_REPOSITORY CI_ACTION_DEPENDENCY_REVIEW_VERSION CI_ACTION_DEPENDENCY_REVIEW_COMMIT
export CI_SECURITY_TOOL_SCORECARD_REPOSITORY CI_SECURITY_TOOL_SCORECARD_VERSION CI_SECURITY_TOOL_SCORECARD_COMMIT CI_SECURITY_TOOL_SCORECARD_ASSET_NAME CI_SECURITY_TOOL_SCORECARD_SHA256 CI_SECURITY_TOOL_OSV_SCANNER_REPOSITORY CI_SECURITY_TOOL_OSV_SCANNER_VERSION CI_SECURITY_TOOL_OSV_SCANNER_COMMIT CI_SECURITY_TOOL_OSV_SCANNER_ASSET_NAME CI_SECURITY_TOOL_OSV_SCANNER_SHA256 CI_SECURITY_TOOL_ACTIONLINT_REPOSITORY CI_SECURITY_TOOL_ACTIONLINT_VERSION CI_SECURITY_TOOL_ACTIONLINT_COMMIT CI_SECURITY_TOOL_ACTIONLINT_ASSET_NAME CI_SECURITY_TOOL_ACTIONLINT_SHA256 CI_SECURITY_TOOL_SHELLCHECK_REPOSITORY CI_SECURITY_TOOL_SHELLCHECK_VERSION CI_SECURITY_TOOL_SHELLCHECK_COMMIT CI_SECURITY_TOOL_SHELLCHECK_ASSET_NAME CI_SECURITY_TOOL_SHELLCHECK_SHA256 CI_SECURITY_TOOL_ZIZMOR_REPOSITORY CI_SECURITY_TOOL_ZIZMOR_VERSION CI_SECURITY_TOOL_ZIZMOR_COMMIT CI_SECURITY_TOOL_ZIZMOR_ASSET_NAME CI_SECURITY_TOOL_ZIZMOR_SHA256 CI_SECURITY_TOOL_GITLEAKS_REPOSITORY CI_SECURITY_TOOL_GITLEAKS_VERSION CI_SECURITY_TOOL_GITLEAKS_COMMIT CI_SECURITY_TOOL_GITLEAKS_ASSET_NAME CI_SECURITY_TOOL_GITLEAKS_SHA256 CI_SECURITY_TOOL_RUFF_REPOSITORY CI_SECURITY_TOOL_RUFF_VERSION CI_SECURITY_TOOL_RUFF_COMMIT CI_SECURITY_TOOL_RUFF_ASSET_NAME CI_SECURITY_TOOL_RUFF_SHA256 CI_SECURITY_TOOL_PYRIGHT_REPOSITORY CI_SECURITY_TOOL_PYRIGHT_VERSION CI_SECURITY_TOOL_PYRIGHT_COMMIT CI_SECURITY_TOOL_PYRIGHT_ASSET_NAME CI_SECURITY_TOOL_PYRIGHT_SHA256
