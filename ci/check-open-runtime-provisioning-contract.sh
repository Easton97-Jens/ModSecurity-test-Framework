#!/bin/sh
# shellcheck shell=sh disable=SC2016
set -eu

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT=$(CDPATH='' cd "$SCRIPT_DIR/.." && pwd)
COMMON_SH="$SCRIPT_DIR/common.sh"
LIGHTTPD_PREPARE_SH="$SCRIPT_DIR/prepare-lighttpd-runtime.sh"
CHECK_ROOT="${TMPDIR:-/tmp}/modsecurity-open-runtime-contract-$$"

failures=0

fail() {
    printf 'open_runtime_provisioning_contract: FAIL: %s\n' "$*" >&2
    failures=$((failures + 1))
}

assert_equal() {
    actual=$1
    expected=$2
    label=$3
    if [ "$actual" != "$expected" ]; then
        fail "$label: expected '$expected', got '$actual'"
    fi
}

assert_function() {
    function_name=$1
    if ! command -v "$function_name" >/dev/null 2>&1; then
        fail "missing function definition: $function_name"
    fi
}

assert_pin() {
    component=$1
    case "$component" in
        ENVOY)
            version=$ENVOY_VERSION
            sha256=$ENVOY_SHA256
            ;;
        TRAEFIK)
            version=$TRAEFIK_VERSION
            sha256=$TRAEFIK_SHA256
            ;;
        LIGHTTPD)
            version=$LIGHTTPD_VERSION
            sha256=$LIGHTTPD_SHA256
            ;;
        *)
            fail "unknown runtime component: $component"
            return
            ;;
    esac

    if ! printf '%s\n' "$version" \
        | grep -Eq '^[0-9]+([.][0-9]+){2}([+.-][0-9A-Za-z.-]+)?$'; then
        fail "${component}_VERSION is not an exact release pin: '$version'"
    fi
    if [ "${#sha256}" -ne 64 ]; then
        fail "${component}_SHA256 is not a 64-character digest"
    else
        case "$sha256" in
            *[!0-9A-Fa-f]*) fail "${component}_SHA256 is not hexadecimal" ;;
        esac
    fi
}

assert_exported() {
    variable_name=$1
    expected_value=$2
    if ! CHECK_VARIABLE="$variable_name" CHECK_EXPECTED="$expected_value" \
        sh -eu -c '
            eval "actual=\${$CHECK_VARIABLE-}"
            [ "$actual" = "$CHECK_EXPECTED" ]
        '
    then
        fail "$variable_name is not exported with value '$expected_value'"
    fi
}

assert_output_line() {
    output=$1
    expected_line=$2
    if ! printf '%s\n' "$output" | grep -Fx -- "$expected_line" >/dev/null; then
        fail "build path output is missing: $expected_line"
    fi
}

assert_contains() {
    path=$1
    expected_text=$2
    label=$3
    if ! grep -F -- "$expected_text" "$path" >/dev/null; then
        fail "$label"
    fi
}

assert_function_contains() {
    function_name=$1
    expected_text=$2
    label=$3
    if ! awk -v function_name="$function_name" '
            $0 == function_name "() {" { in_function = 1 }
            in_function { print }
            in_function && $0 == "}" { exit }
        ' "$COMMON_SH" | grep -F -- "$expected_text" >/dev/null
    then
        fail "$label"
    fi
}

# Ignore caller overrides so this check verifies the repository defaults.
unset ENVOY_VERSION ENVOY_SHA256 ENVOY_COMPONENT_ROOT ENVOY_SOURCE_ROOT ENVOY_BUILD_ROOT ENVOY_BIN
unset TRAEFIK_VERSION TRAEFIK_SHA256 TRAEFIK_COMPONENT_ROOT TRAEFIK_SOURCE_ROOT TRAEFIK_BUILD_ROOT TRAEFIK_BIN
unset LIGHTTPD_VERSION LIGHTTPD_SHA256 LIGHTTPD_COMPONENT_ROOT LIGHTTPD_SOURCE_DIR LIGHTTPD_BUILD_ROOT
unset LIGHTTPD_INCLUDE_DIR LIGHTTPD_CONNECTOR_BUILD_ROOT LIGHTTPD_MODULE_DIR LIGHTTPD_BIN
unset VERIFIED_COMPONENT_CACHE CONNECTOR_COMPONENT_CACHE VERIFIED_RUN_ROOT BUILD_ROOT

CONNECTOR_ROOT=$FRAMEWORK_ROOT
VERIFIED_RUN_ROOT=$CHECK_ROOT
BUILD_ROOT=$CHECK_ROOT/build
export FRAMEWORK_ROOT CONNECTOR_ROOT VERIFIED_RUN_ROOT BUILD_ROOT

# common.sh is deliberately passive. Sourcing it and printing/exporting paths
# must not create the configured runtime root.
# shellcheck source=ci/common.sh
. "$COMMON_SH"

for function_name in \
    envoy_build_paths traefik_build_paths lighttpd_build_paths \
    require_or_provision_envoy require_or_provision_traefik require_or_provision_lighttpd
do
    assert_function "$function_name"
done

for component in ENVOY TRAEFIK LIGHTTPD; do
    assert_pin "$component"
done

if ! ci_runtime_version_matches 1.2.3 'runtime v1.2.3'; then
    fail 'exact runtime version matching rejected v1.2.3'
fi
if ci_runtime_version_matches 1.2.3 'runtime v1.2.30'; then
    fail 'runtime version matching accepted the prefix 1.2.3 from 1.2.30'
fi
if [ -x /bin/echo ]; then
    if ! ci_runtime_binary_matches_version /bin/echo 1.2.3 1.2.3; then
        fail 'runtime binary version matching rejected an exact version token'
    fi
    if ci_runtime_binary_matches_version /bin/echo 1.2.3 1.2.30; then
        fail 'runtime binary version matching accepted a longer cached version'
    fi
fi

assert_function_contains require_or_provision_envoy \
    'ci_runtime_binary_matches_version "$ENVOY_BIN" "$ENVOY_VERSION" --version' \
    'require_or_provision_envoy does not verify the cached binary version'
assert_function_contains require_or_provision_traefik \
    'ci_runtime_binary_matches_version "$TRAEFIK_BIN" "$TRAEFIK_VERSION" version' \
    'require_or_provision_traefik does not verify the cached binary version'
assert_function_contains require_or_provision_lighttpd \
    'ci_runtime_binary_matches_version "$LIGHTTPD_BIN" "$LIGHTTPD_VERSION" -v' \
    'require_or_provision_lighttpd does not verify the cached binary version'

envoy_paths=$(envoy_build_paths)
envoy_build_paths >/dev/null
assert_equal "$ENVOY_SOURCE_ROOT" "$ENVOY_COMPONENT_ROOT/src/envoy-$ENVOY_VERSION" ENVOY_SOURCE_ROOT
assert_equal "$ENVOY_BUILD_ROOT" "$BUILD_ROOT/envoy-connector" ENVOY_BUILD_ROOT
assert_exported ENVOY_SOURCE_ROOT "$ENVOY_SOURCE_ROOT"
assert_exported ENVOY_BUILD_ROOT "$ENVOY_BUILD_ROOT"
assert_output_line "$envoy_paths" "ENVOY_SOURCE_ROOT=$ENVOY_SOURCE_ROOT"
assert_output_line "$envoy_paths" "ENVOY_BUILD_ROOT=$ENVOY_BUILD_ROOT"

traefik_paths=$(traefik_build_paths)
traefik_build_paths >/dev/null
assert_equal "$TRAEFIK_SOURCE_ROOT" "$TRAEFIK_COMPONENT_ROOT/src/traefik-$TRAEFIK_VERSION" TRAEFIK_SOURCE_ROOT
assert_equal "$TRAEFIK_BUILD_ROOT" "$BUILD_ROOT/traefik-connector" TRAEFIK_BUILD_ROOT
assert_exported TRAEFIK_SOURCE_ROOT "$TRAEFIK_SOURCE_ROOT"
assert_exported TRAEFIK_BUILD_ROOT "$TRAEFIK_BUILD_ROOT"
assert_output_line "$traefik_paths" "TRAEFIK_SOURCE_ROOT=$TRAEFIK_SOURCE_ROOT"
assert_output_line "$traefik_paths" "TRAEFIK_BUILD_ROOT=$TRAEFIK_BUILD_ROOT"

lighttpd_paths=$(lighttpd_build_paths)
lighttpd_build_paths >/dev/null
assert_equal "$LIGHTTPD_SOURCE_DIR" "$LIGHTTPD_COMPONENT_ROOT/src/lighttpd-$LIGHTTPD_VERSION" LIGHTTPD_SOURCE_DIR
assert_equal "$LIGHTTPD_INCLUDE_DIR" "$LIGHTTPD_SOURCE_DIR/src" LIGHTTPD_INCLUDE_DIR
assert_exported LIGHTTPD_SOURCE_DIR "$LIGHTTPD_SOURCE_DIR"
assert_exported LIGHTTPD_INCLUDE_DIR "$LIGHTTPD_INCLUDE_DIR"
assert_output_line "$lighttpd_paths" "LIGHTTPD_SOURCE_DIR=$LIGHTTPD_SOURCE_DIR"
assert_output_line "$lighttpd_paths" "LIGHTTPD_INCLUDE_DIR=$LIGHTTPD_INCLUDE_DIR"

# Keep the lighttpd preparer aligned with the path contract without executing
# its download/build branches.
assert_contains "$LIGHTTPD_PREPARE_SH" \
    'LIGHTTPD_SOURCE_STAGE_DIR="${LIGHTTPD_SOURCE_STAGE_DIR:-${LIGHTTPD_SOURCE_DIR:-$LIGHTTPD_COMPONENT_ROOT/src/lighttpd-$LIGHTTPD_VERSION}}"' \
    'prepare-lighttpd-runtime.sh does not consume LIGHTTPD_SOURCE_DIR'
assert_contains "$LIGHTTPD_PREPARE_SH" \
    '[ -d "$LIGHTTPD_SOURCE_STAGE_DIR" ]' \
    'prepare-lighttpd-runtime.sh can accept a staged source tree'
assert_contains "$COMMON_SH" \
    '[ -f "$LIGHTTPD_INCLUDE_DIR/plugin.h" ]' \
    'require_or_provision_lighttpd does not require exported lighttpd headers'

if [ -e "$CHECK_ROOT" ]; then
    fail "passive path checks created the runtime root: $CHECK_ROOT"
fi

if [ "$failures" -ne 0 ]; then
    exit 1
fi

printf 'open_runtime_provisioning_contract: PASS\n'
