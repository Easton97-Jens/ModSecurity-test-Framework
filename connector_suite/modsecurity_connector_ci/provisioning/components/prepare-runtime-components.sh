#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
FRAMEWORK_ROOT="${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
: "${CONNECTOR_TEST_PROFILE:?CONNECTOR_TEST_PROFILE is required explicitly}"
PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
PYTHONSAFEPATH=1
PYTHONNOUSERSITE=1
export TEST_ROOT PYTHONPATH PYTHONSAFEPATH PYTHONNOUSERSITE
PYTHON="${PYTHON:-python3}"
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
VERIFIED_TMP_ROOT="${VERIFIED_TMP_ROOT:-$VERIFIED_RUN_ROOT/tmp}"
VERIFIED_LOG_ROOT="${VERIFIED_LOG_ROOT:-$VERIFIED_RUN_ROOT/logs}"
CACHE_ROOT="${CACHE_ROOT:-$VERIFIED_RUN_ROOT/cache-v2}"
VERIFIED_COMPONENT_CACHE="${VERIFIED_COMPONENT_CACHE:-$CACHE_ROOT/shared}"
RUNTIME_REPORT_OUTPUT_ROOT="${RUNTIME_REPORT_OUTPUT_ROOT:-$VERIFIED_BUILD_ROOT/runtime-component-reports}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
TMP_ROOT="${TMP_ROOT:-$VERIFIED_TMP_ROOT}"
LOG_ROOT="${LOG_ROOT:-$VERIFIED_LOG_ROOT}"
MRTS_NATIVE_ROOT="${MRTS_NATIVE_ROOT:-$BUILD_ROOT/mrts-native}"

if [ -z "${CONNECTOR_COMPONENT_CACHE:-}" ]; then
    CONNECTOR_COMPONENT_CACHE="$VERIFIED_COMPONENT_CACHE"
fi

export CONNECTOR_ROOT FRAMEWORK_ROOT BUILD_ROOT TMP_ROOT LOG_ROOT MRTS_NATIVE_ROOT CACHE_ROOT VERIFIED_COMPONENT_CACHE CONNECTOR_COMPONENT_CACHE RUNTIME_REPORT_OUTPUT_ROOT

REPO_ROOT="$CONNECTOR_ROOT"
# Resolve the Framework tuple before sourcing it locally.  The bridge accepts
# an inherited tuple only after an independent byte-for-byte Framework match.
/bin/sh "$CONNECTOR_ROOT/ci/tools/print-framework-apr-util-env.sh" "$FRAMEWORK_ROOT" "$CONNECTOR_ROOT" >/dev/null
. "$FRAMEWORK_ROOT/ci/lib/common.sh"
ci_require_apr_util_pinned_provenance || exit 77
ci_validate_https_runtime_url_config || exit 77

export MODSECURITY_REPO_URL MODSECURITY_GIT_REF MODSECURITY_V3_GIT_URL MODSECURITY_V3_GIT_REF
export MODSECURITY_APACHE_GIT_URL MODSECURITY_APACHE_GIT_REF MODSECURITY_NGINX_GIT_URL MODSECURITY_NGINX_GIT_REF
export CRS_REPO_URL CRS_GIT_REF
export HTTPD_VERSION HTTPD_SOURCE_URL HTTPD_SHA256 HTTPD_SHA256_URL
export APR_VERSION APR_SOURCE_URL APR_SHA256 APR_SHA256_URL
export APR_UTIL_VERSION APR_UTIL_SOURCE_URL APR_UTIL_SHA256 APR_UTIL_SHA256_URL
export PCRE2_VERSION PCRE2_SOURCE_URL PCRE2_SHA256 PCRE2_SHA256_URL
export NGINX_SOURCE_MODE NGINX_SOURCE_REPO_URL NGINX_GITHUB_REPO NGINX_RELEASE_TAG NGINX_SOURCE_GIT_REF NGINX_RELEASE_ASSET_NAME NGINX_SHA256 NGINX_REQUIRE_PINNED_PROVENANCE
export HAPROXY_VERSION HAPROXY_SOURCE_URL HAPROXY_SHA256_URL HAPROXY_SHA256
export GO_FTW_SOURCE_URL GO_FTW_PROMPT_EXPECTED_LATEST GO_FTW_GIT_REF GO_FTW_BIN
export ALBEDO_SOURCE_URL ALBEDO_PROMPT_EXPECTED_LATEST ALBEDO_GIT_REF ALBEDO_BIN
export EXPAT_SOURCE_URL EXPAT_GIT_REF EXPAT_GIT_URL EXPAT_PROMPT_EXPECTED_LATEST EXPAT_PREFIX EXPAT_BUILD_DIR

assert_safe_runtime_path "$BUILD_ROOT" BUILD_ROOT || exit 77
assert_safe_runtime_path "$TMP_ROOT" TMP_ROOT || exit 77
assert_safe_runtime_path "$LOG_ROOT" LOG_ROOT || exit 77
assert_safe_runtime_path "$MRTS_NATIVE_ROOT" MRTS_NATIVE_ROOT || exit 77
assert_safe_runtime_path "$CONNECTOR_COMPONENT_CACHE" CONNECTOR_COMPONENT_CACHE || exit 77
assert_safe_runtime_path "$RUNTIME_REPORT_OUTPUT_ROOT" RUNTIME_REPORT_OUTPUT_ROOT || exit 77
assert_not_system_path_for_write "$RUNTIME_REPORT_OUTPUT_ROOT/reports/testing/generated" runtime_component_report_dir || exit 77

mkdir -p "$CONNECTOR_COMPONENT_CACHE" "$MRTS_NATIVE_ROOT" "$RUNTIME_REPORT_OUTPUT_ROOT/reports/testing/generated"

snapshot_reserved_here=0
if [ -z "${RUNTIME_COMPONENT_ENV_SNAPSHOT:-}" ]; then
    RUNTIME_COMPONENT_ENV_SNAPSHOT=$(sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/reserve-runtime-env-snapshot.sh" "$RUNTIME_REPORT_OUTPUT_ROOT") || exit $?
    snapshot_reserved_here=1
fi
assert_not_system_path_for_write "$RUNTIME_COMPONENT_ENV_SNAPSHOT" runtime_component_env_snapshot || exit 77
export RUNTIME_COMPONENT_ENV_SNAPSHOT

set +e
"$PYTHON" -P "$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/components/prepare-runtime-components.py" \
    --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT" \
    --cache-root "$CONNECTOR_COMPONENT_CACHE" \
    --output-root "$RUNTIME_REPORT_OUTPUT_ROOT" \
    --build-root "$BUILD_ROOT" \
    --native-root "$MRTS_NATIVE_ROOT" \
    --runtime-env-snapshot "$RUNTIME_COMPONENT_ENV_SNAPSHOT" \
    --runtime-env-snapshot-contract "${RUNTIME_COMPONENT_SNAPSHOT_CONTRACT:-generic}" \
    --target-connector "${RUNTIME_COMPONENT_TARGET:-all}"
prepare_rc=$?
set -e
if [ "$prepare_rc" -ne 0 ]; then
    if [ "$snapshot_reserved_here" -eq 1 ]; then
        rm -f "$RUNTIME_COMPONENT_ENV_SNAPSHOT"
    fi
    exit "$prepare_rc"
fi
