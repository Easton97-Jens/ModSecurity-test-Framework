#!/bin/sh
set -eu

MODE="${1:-inventory}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
FRAMEWORK_ROOT="${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
: "${CONNECTOR_TEST_PROFILE:?CONNECTOR_TEST_PROFILE is required explicitly}"
PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
PYTHONSAFEPATH=1
PYTHONNOUSERSITE=1
export TEST_ROOT PYTHONPATH PYTHONSAFEPATH PYTHONNOUSERSITE
REPO_ROOT="$CONNECTOR_ROOT"

# Inventory must report the same Framework-owned tuple as provisioning and
# independently rejects any inherited tuple that is not the canonical one.
/bin/sh "$CONNECTOR_ROOT/ci/tools/print-framework-apr-util-env.sh" "$FRAMEWORK_ROOT" "$CONNECTOR_ROOT" >/dev/null
# shellcheck disable=SC1091
. "$FRAMEWORK_ROOT/ci/lib/common.sh"
ci_require_apr_util_pinned_provenance || exit 77
ci_validate_https_runtime_url_config || exit 77

sha_status() {
    value=$1
    if [ -n "$value" ] && [ "$value" != "TODO_PIN_SHA256" ]; then
        printf '%s\n' pinned
    else
        printf '%s\n' missing
    fi
}

can_download_with_opt_in() {
    version=$1
    download_url=$2
    sha256=$3
    if [ -n "$version" ] && [ "$version" != "TODO_PIN_VERSION" ] \
        && [ -n "$download_url" ] && [ -n "$sha256" ] \
        && [ "$sha256" != "TODO_PIN_SHA256" ]; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

resolved_binary() {
    binary=$1
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        printf '%s\n' "$binary"
    else
        printf '%s\n' '<missing>'
    fi
}

binary_status() {
    binary=$1
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        printf '%s\n' binary_present
    else
        printf '%s\n' binary_missing
    fi
}

source_staged_status() {
    source_dir=$1
    if [ -d "$source_dir" ]; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

json_bool_field() {
    json_file=$1
    json_field=$2
    if [ ! -f "$json_file" ]; then
        printf '%s\n' false
        return 0
    fi
    if grep -Eq "\"$json_field\"[[:space:]]*:[[:space:]]*true" "$json_file"; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

json_string_field_equals() {
    json_file=$1
    json_field=$2
    expected_value=$3
    if [ ! -f "$json_file" ]; then
        return 1
    fi
    grep -Eq "\"$json_field\"[[:space:]]*:[[:space:]]*\"$expected_value\"" "$json_file"
}

json_contains_string() {
    json_file=$1
    string_value=$2
    if [ ! -f "$json_file" ]; then
        return 1
    fi
    grep -Eq "\"$string_value\"" "$json_file"
}

json_missing_dependency_contains() {
    json_file=$1
    dependency_value=$2
    if [ ! -f "$json_file" ]; then
        return 1
    fi
    awk -v value="$dependency_value" '
        /"missing_dependencies"[[:space:]]*:/ { in_missing = 1 }
        in_missing && index($0, "\"" value "\"") { found = 1 }
        in_missing && /\]/ { in_missing = 0 }
        END { exit found ? 0 : 1 }
    ' "$json_file"
}

json_string_field() {
    json_file=$1
    json_field=$2
    if [ ! -f "$json_file" ]; then
        return 1
    fi
    sed -n "s/.*\"$json_field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$json_file" | sed -n '1p'
}

local_status_for_binary() {
    binary=$1
    can_download=$2
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        printf '%s\n' ready
    elif [ "$can_download" = "true" ]; then
        printf '%s\n' missing_download_opt_in_available
    else
        printf '%s\n' blocked_source_pin_missing
    fi
}

connector_result_root() {
    result_connector=$1
    case "$result_connector" in
        envoy) printf '%s\n' "$ENVOY_RESULT_ROOT" ;;
        traefik) printf '%s\n' "$TRAEFIK_RESULT_ROOT" ;;
        lighttpd) printf '%s\n' "$LIGHTTPD_RESULT_ROOT" ;;
        *) printf '%s\n' "" ;;
    esac
}

ruleset_result_file() {
    result_root=$1
    ruleset=$2
    case "$ruleset" in
        runtime) printf '%s\n' "$result_root/runtime-result.json" ;;
        targeted) printf '%s\n' "$result_root/targeted-result.json" ;;
        crs) printf '%s\n' "$result_root/crs-result.json" ;;
        crs-secondary) printf '%s\n' "$result_root/crs-secondary-result.json" ;;
        current) printf '%s\n' "$result_root/result.json" ;;
        *) printf '%s\n' "" ;;
    esac
}

crs_result_file_for_case() {
    result_root=$1
    smoke_case=$2
    case "$smoke_case" in
        minimal) ruleset_result_file "$result_root" crs ;;
        secondary) ruleset_result_file "$result_root" crs-secondary ;;
        *) printf '%s\n' "" ;;
    esac
}

crs_current_result_matches_case() {
    current_result=$1
    smoke_case=$2
    if [ ! -f "$current_result" ]; then
        return 1
    fi
    if json_string_field_equals "$current_result" crs_smoke_case "$smoke_case"; then
        return 0
    fi
    if [ "$smoke_case" = "minimal" ]; then
        current_case=$(json_string_field "$current_result" crs_smoke_case || true)
        if [ -z "$current_case" ]; then
            return 0
        fi
    fi
    return 1
}

runtime_smoke_verified_for() {
    result_root=$1
    runtime_result=$(ruleset_result_file "$result_root" runtime)
    current_result=$(ruleset_result_file "$result_root" current)
    if [ "$(json_bool_field "$runtime_result" runtime_verified)" = "true" ]; then
        printf '%s\n' true
    elif json_string_field_equals "$current_result" decision_backend simple \
        && [ "$(json_bool_field "$current_result" runtime_verified)" = "true" ]; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

targeted_modsecurity_smoke_verified_for() {
    result_root=$1
    targeted_result=$(ruleset_result_file "$result_root" targeted)
    current_result=$(ruleset_result_file "$result_root" current)
    if json_string_field_equals "$targeted_result" modsecurity_ruleset targeted \
        && [ "$(json_bool_field "$targeted_result" modsecurity_backend_verified)" = "true" ]; then
        printf '%s\n' true
    elif json_string_field_equals "$current_result" modsecurity_ruleset targeted \
        && [ "$(json_bool_field "$current_result" modsecurity_backend_verified)" = "true" ]; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

crs_smoke_verified_for_case() {
    result_root=$1
    smoke_case=$2
    bool_field=$3
    crs_result=$(crs_result_file_for_case "$result_root" "$smoke_case")
    current_result=$(ruleset_result_file "$result_root" current)
    if json_string_field_equals "$crs_result" modsecurity_ruleset crs \
        && [ "$(json_bool_field "$crs_result" "$bool_field")" = "true" ]; then
        printf '%s\n' true
    elif crs_current_result_matches_case "$current_result" "$smoke_case" \
        && json_string_field_equals "$current_result" modsecurity_ruleset crs \
        && [ "$(json_bool_field "$current_result" "$bool_field")" = "true" ]; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

minimal_crs_smoke_verified_for() {
    result_root=$1
    crs_smoke_verified_for_case "$result_root" minimal crs_minimal_smoke_verified
}

secondary_crs_smoke_verified_for() {
    result_root=$1
    crs_smoke_verified_for_case "$result_root" secondary crs_secondary_smoke_verified
}

crs_blocked_status_for_case() {
    result_root=$1
    smoke_case=$2
    dependency=$3
    crs_result=$(crs_result_file_for_case "$result_root" "$smoke_case")
    current_result=$(ruleset_result_file "$result_root" current)
    if json_string_field_equals "$crs_result" modsecurity_ruleset crs \
        && json_string_field_equals "$crs_result" status BLOCKED \
        && json_missing_dependency_contains "$crs_result" "$dependency"; then
        printf '%s\n' true
    elif crs_current_result_matches_case "$current_result" "$smoke_case" \
        && json_string_field_equals "$current_result" modsecurity_ruleset crs \
        && json_string_field_equals "$current_result" status BLOCKED \
        && json_missing_dependency_contains "$current_result" "$dependency"; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

crs_probe_not_blocked_for_case() {
    result_root=$1
    smoke_case=$2
    crs_result=$(crs_result_file_for_case "$result_root" "$smoke_case")
    current_result=$(ruleset_result_file "$result_root" current)
    if json_string_field_equals "$crs_result" modsecurity_ruleset crs \
        && json_string_field_equals "$crs_result" status FAIL; then
        printf '%s\n' true
    elif crs_current_result_matches_case "$current_result" "$smoke_case" \
        && json_string_field_equals "$current_result" modsecurity_ruleset crs \
        && json_string_field_equals "$current_result" status FAIL; then
        printf '%s\n' true
    else
        printf '%s\n' false
    fi
}

crs_metadata_field_for_case() {
    result_root=$1
    smoke_case=$2
    metadata_field=$3
    fallback=$4
    crs_result=$(crs_result_file_for_case "$result_root" "$smoke_case")
    current_result=$(ruleset_result_file "$result_root" current)
    metadata_value=$(json_string_field "$crs_result" "$metadata_field" || true)
    if [ -z "$metadata_value" ] && crs_current_result_matches_case "$current_result" "$smoke_case"; then
        metadata_value=$(json_string_field "$current_result" "$metadata_field" || true)
    fi
    if [ -n "$metadata_value" ]; then
        printf '%s\n' "$metadata_value"
    else
        printf '%s\n' "$fallback"
    fi
}

crs_metadata_field_for() {
    result_root=$1
    field=$2
    fallback=$3
    crs_metadata_field_for_case "$result_root" minimal "$field" "$fallback"
}

secondary_crs_evidence_for() {
    result_root=$1
    evidence=$(crs_metadata_field_for_case "$result_root" secondary audit_log_path "")
    if [ -z "$evidence" ]; then
        evidence=$(crs_metadata_field_for_case "$result_root" secondary decision_log_path "")
    fi
    printf '%s\n' "$evidence"
}

secondary_crs_status_for() {
    result_root=$1
    runtime_dependency=$2
    if [ "$(secondary_crs_smoke_verified_for "$result_root")" = "true" ]; then
        printf '%s\n' secondary_crs_smoke_verified
    elif [ "$(crs_blocked_status_for_case "$result_root" secondary crs)" = "true" ]; then
        printf '%s\n' secondary_crs_smoke_blocked_missing_crs
    elif [ "$(crs_blocked_status_for_case "$result_root" secondary libmodsecurity)" = "true" ]; then
        printf '%s\n' secondary_crs_smoke_blocked_missing_modsecurity
    elif [ "$(crs_blocked_status_for_case "$result_root" secondary "$runtime_dependency")" = "true" ]; then
        printf '%s\n' secondary_crs_smoke_blocked_runtime
    elif [ "$(crs_probe_not_blocked_for_case "$result_root" secondary)" = "true" ]; then
        printf '%s\n' secondary_crs_probe_not_blocked
    else
        printf '%s\n' not_run
    fi
}

print_binary_component() {
    name=$1
    version=$2
    source_url=$3
    install_docs=$4
    download_url=$5
    sha256=$6
    sha256_url=$7
    expected_binary=$8
    integration_mode=$9

    sha_state=$(sha_status "$sha256")
    can_download=$(can_download_with_opt_in "$version" "$download_url" "$sha256")
    resolved=$(resolved_binary "$expected_binary")
    result_root=$(connector_result_root "$name")
    runtime_smoke_verified=$(runtime_smoke_verified_for "$result_root")
    targeted_modsecurity_smoke_verified=$(targeted_modsecurity_smoke_verified_for "$result_root")
    minimal_crs_smoke_verified=$(minimal_crs_smoke_verified_for "$result_root")
    secondary_crs_smoke_verified=$(secondary_crs_smoke_verified_for "$result_root")
    minimal_crs_smoke_blocked_missing_crs=$(crs_blocked_status_for_case "$result_root" minimal crs)
    minimal_crs_smoke_blocked_missing_modsecurity=$(crs_blocked_status_for_case "$result_root" minimal libmodsecurity)
    minimal_crs_smoke_blocked_runtime=$(crs_blocked_status_for_case "$result_root" minimal "$name")
    secondary_crs_smoke_blocked_missing_crs=$(crs_blocked_status_for_case "$result_root" secondary crs)
    secondary_crs_smoke_blocked_missing_modsecurity=$(
        crs_blocked_status_for_case "$result_root" secondary libmodsecurity
    )
    secondary_crs_smoke_blocked_runtime=$(crs_blocked_status_for_case "$result_root" secondary "$name")
    secondary_crs_probe_not_blocked=$(crs_probe_not_blocked_for_case "$result_root" secondary)
    secondary_crs_status=$(secondary_crs_status_for "$result_root" "$name")
    secondary_crs_rule_id=$(crs_metadata_field_for_case "$result_root" secondary crs_rule_id "")
    secondary_crs_rule_message=$(crs_metadata_field_for_case "$result_root" secondary crs_rule_message "")
    secondary_crs_evidence=$(secondary_crs_evidence_for "$result_root")
    crs_source_dir=$(crs_metadata_field_for "$result_root" crs_source_dir "$CRS_SOURCE_DIR")
    crs_git_ref=$(crs_metadata_field_for "$result_root" crs_git_ref "$CRS_GIT_REF")
    crs_runtime_dir=$(crs_metadata_field_for "$result_root" crs_runtime_dir "$result_root/crs-smoke")
    if [ "$secondary_crs_status" != "not_run" ]; then
        local_status=$secondary_crs_status
        component_status=$secondary_crs_status
    elif [ "$minimal_crs_smoke_verified" = "true" ]; then
        local_status=minimal_crs_smoke_verified
        component_status=minimal_crs_smoke_verified
    elif [ "$minimal_crs_smoke_blocked_missing_crs" = "true" ]; then
        local_status=minimal_crs_smoke_blocked_missing_crs
        component_status=minimal_crs_smoke_blocked_missing_crs
    elif [ "$minimal_crs_smoke_blocked_missing_modsecurity" = "true" ]; then
        local_status=minimal_crs_smoke_blocked_missing_modsecurity
        component_status=minimal_crs_smoke_blocked_missing_modsecurity
    elif [ "$minimal_crs_smoke_blocked_runtime" = "true" ]; then
        local_status=minimal_crs_smoke_blocked_runtime
        component_status=minimal_crs_smoke_blocked_runtime
    elif [ "$targeted_modsecurity_smoke_verified" = "true" ]; then
        local_status=targeted_modsecurity_smoke_verified
        component_status=targeted_modsecurity_smoke_verified
    elif [ "$runtime_smoke_verified" = "true" ]; then
        local_status=runtime_smoke_verified
        component_status=runtime_smoke_verified
    else
        local_status=$(local_status_for_binary "$expected_binary" "$can_download")
        component_status=source_pinned_download_opt_in_required
    fi

    printf 'name=%s\n' "$name"
    printf 'version=%s\n' "$version"
    printf 'source_url=%s\n' "$source_url"
    if [ -n "$install_docs" ]; then
        printf 'install_docs=%s\n' "$install_docs"
    fi
    printf 'download_url=%s\n' "$download_url"
    printf 'sha256_status=%s\n' "$sha_state"
    printf 'sha256=%s\n' "$sha256"
    printf 'sha256_url=%s\n' "$sha256_url"
    printf 'expected_binary=%s\n' "$expected_binary"
    if [ "$MODE" = "inventory" ]; then
        printf 'resolved_binary=%s\n' "$resolved"
    fi
    printf 'can_download_with_opt_in=%s\n' "$can_download"
    printf 'runtime_smoke_verified=%s\n' "$runtime_smoke_verified"
    printf 'targeted_modsecurity_smoke_verified=%s\n' "$targeted_modsecurity_smoke_verified"
    printf 'minimal_crs_smoke_verified=%s\n' "$minimal_crs_smoke_verified"
    printf 'minimal_crs_smoke_blocked_missing_crs=%s\n' "$minimal_crs_smoke_blocked_missing_crs"
    printf 'minimal_crs_smoke_blocked_missing_modsecurity=%s\n' "$minimal_crs_smoke_blocked_missing_modsecurity"
    printf 'minimal_crs_smoke_blocked_runtime=%s\n' "$minimal_crs_smoke_blocked_runtime"
    printf 'secondary_crs_smoke_verified=%s\n' "$secondary_crs_smoke_verified"
    printf 'secondary_crs_smoke_blocked_missing_crs=%s\n' "$secondary_crs_smoke_blocked_missing_crs"
    printf 'secondary_crs_smoke_blocked_missing_modsecurity=%s\n' "$secondary_crs_smoke_blocked_missing_modsecurity"
    printf 'secondary_crs_smoke_blocked_runtime=%s\n' "$secondary_crs_smoke_blocked_runtime"
    printf 'secondary_crs_probe_not_blocked=%s\n' "$secondary_crs_probe_not_blocked"
    printf 'secondary_crs_rule_id=%s\n' "$secondary_crs_rule_id"
    printf 'secondary_crs_rule_message=%s\n' "$secondary_crs_rule_message"
    printf 'secondary_crs_evidence=%s\n' "$secondary_crs_evidence"
    printf 'secondary_crs_status=%s\n' "$secondary_crs_status"
    printf 'crs_source_dir=%s\n' "$crs_source_dir"
    printf 'crs_git_ref=%s\n' "$crs_git_ref"
    printf 'crs_runtime_dir=%s\n' "$crs_runtime_dir"
    printf 'local_status=%s\n' "$local_status"
    printf 'enabled=%s\n' "$can_download"
    printf 'status=%s\n' "$component_status"
    printf 'integration_mode=%s\n' "$integration_mode"
    printf '\n'
}

print_lighttpd_component() {
    source_dir="$LIGHTTPD_COMPONENT_ROOT/src/lighttpd-$LIGHTTPD_VERSION"
    smoke_result="$LIGHTTPD_RESULT_ROOT/result.json"
    result_root=$(connector_result_root lighttpd)
    missing_deps_log="$LIGHTTPD_LOG_ROOT/prepare-runtime/build-dependencies.missing"
    sha_state=$(sha_status "$LIGHTTPD_SHA256")
    can_download=$(can_download_with_opt_in "$LIGHTTPD_VERSION" "$LIGHTTPD_DOWNLOAD_URL" "$LIGHTTPD_SHA256")
    source_staged=$(source_staged_status "$source_dir")
    runtime_binary_status=$(binary_status "$LIGHTTPD_BIN")
    runtime_binary_produced=false
    if [ "$runtime_binary_status" = "binary_present" ]; then
        runtime_binary_produced=true
    fi
    runtime_smoke_verified=$(runtime_smoke_verified_for "$result_root")
    targeted_modsecurity_smoke_verified=$(targeted_modsecurity_smoke_verified_for "$result_root")
    minimal_crs_smoke_verified=$(minimal_crs_smoke_verified_for "$result_root")
    secondary_crs_smoke_verified=$(secondary_crs_smoke_verified_for "$result_root")
    minimal_crs_smoke_blocked_missing_crs=$(crs_blocked_status_for_case "$result_root" minimal crs)
    minimal_crs_smoke_blocked_missing_modsecurity=$(crs_blocked_status_for_case "$result_root" minimal libmodsecurity)
    minimal_crs_smoke_blocked_runtime=$(crs_blocked_status_for_case "$result_root" minimal lighttpd)
    secondary_crs_smoke_blocked_missing_crs=$(crs_blocked_status_for_case "$result_root" secondary crs)
    secondary_crs_smoke_blocked_missing_modsecurity=$(
        crs_blocked_status_for_case "$result_root" secondary libmodsecurity
    )
    secondary_crs_smoke_blocked_runtime=$(crs_blocked_status_for_case "$result_root" secondary lighttpd)
    secondary_crs_probe_not_blocked=$(crs_probe_not_blocked_for_case "$result_root" secondary)
    secondary_crs_status=$(secondary_crs_status_for "$result_root" lighttpd)
    secondary_crs_rule_id=$(crs_metadata_field_for_case "$result_root" secondary crs_rule_id "")
    secondary_crs_rule_message=$(crs_metadata_field_for_case "$result_root" secondary crs_rule_message "")
    secondary_crs_evidence=$(secondary_crs_evidence_for "$result_root")
    crs_source_dir=$(crs_metadata_field_for "$result_root" crs_source_dir "$CRS_SOURCE_DIR")
    crs_git_ref=$(crs_metadata_field_for "$result_root" crs_git_ref "$CRS_GIT_REF")
    crs_runtime_dir=$(crs_metadata_field_for "$result_root" crs_runtime_dir "$result_root/crs-smoke")
    targeted_modsecurity_smoke_blocked_missing_deps=false
    if json_string_field_equals "$smoke_result" decision_backend libmodsecurity \
        && json_string_field_equals "$smoke_result" status BLOCKED \
        && json_contains_string "$smoke_result" libmodsecurity; then
        targeted_modsecurity_smoke_blocked_missing_deps=true
    fi
    resolved=$(resolved_binary "$LIGHTTPD_BIN")
    if [ "$secondary_crs_status" != "not_run" ]; then
        local_status=$secondary_crs_status
        component_status=$secondary_crs_status
    elif [ "$minimal_crs_smoke_verified" = "true" ]; then
        local_status=minimal_crs_smoke_verified
        component_status=minimal_crs_smoke_verified
    elif [ "$minimal_crs_smoke_blocked_missing_crs" = "true" ]; then
        local_status=minimal_crs_smoke_blocked_missing_crs
        component_status=minimal_crs_smoke_blocked_missing_crs
    elif [ "$minimal_crs_smoke_blocked_missing_modsecurity" = "true" ]; then
        local_status=minimal_crs_smoke_blocked_missing_modsecurity
        component_status=minimal_crs_smoke_blocked_missing_modsecurity
    elif [ "$minimal_crs_smoke_blocked_runtime" = "true" ]; then
        local_status=minimal_crs_smoke_blocked_runtime
        component_status=minimal_crs_smoke_blocked_runtime
    elif [ "$targeted_modsecurity_smoke_verified" = "true" ]; then
        local_status=targeted_modsecurity_smoke_verified
        component_status=targeted_modsecurity_smoke_verified
    elif [ "$targeted_modsecurity_smoke_blocked_missing_deps" = "true" ]; then
        local_status=targeted_modsecurity_smoke_blocked_missing_deps
        component_status=targeted_modsecurity_smoke_blocked_missing_deps
    elif [ "$runtime_smoke_verified" = "true" ]; then
        local_status=runtime_smoke_verified
        component_status=runtime_smoke_verified
    elif [ "$runtime_binary_status" = "binary_present" ]; then
        local_status=ready
        component_status=runtime_binary_staged
    elif [ -f "$missing_deps_log" ]; then
        local_status=build_blocked_missing_dependencies
        component_status=build_blocked_missing_dependencies
    elif [ "$source_staged" = "true" ]; then
        local_status=source_pinned_build_required
        component_status=source_pinned_build_required
    elif [ "$can_download" = "true" ]; then
        local_status=source_missing_download_opt_in_available
        component_status=source_pinned_build_opt_in_required
    else
        local_status=blocked_source_pin_missing
        component_status=blocked_source_pin_missing
    fi

    printf 'name=lighttpd\n'
    printf 'version=%s\n' "$LIGHTTPD_VERSION"
    printf 'source_url=%s\n' "$LIGHTTPD_SOURCE_URL"
    printf 'release_index_url=%s\n' "$LIGHTTPD_RELEASE_INDEX_URL"
    printf 'latest_url=%s\n' "$LIGHTTPD_LATEST_URL"
    printf 'download_url=%s\n' "$LIGHTTPD_DOWNLOAD_URL"
    printf 'sha256_status=%s\n' "$sha_state"
    printf 'sha256=%s\n' "$LIGHTTPD_SHA256"
    printf 'sha256_url=%s\n' "$LIGHTTPD_SHA256_URL"
    printf 'expected_binary=%s\n' "$LIGHTTPD_BIN"
    if [ "$MODE" = "inventory" ]; then
        printf 'resolved_binary=%s\n' "$resolved"
    fi
    printf 'can_download_with_opt_in=%s\n' "$can_download"
    printf 'build_supported=true\n'
    printf 'build_requires_opt_in=true\n'
    printf 'source_staged=%s\n' "$source_staged"
    printf 'source_dir=%s\n' "$source_dir"
    printf 'runtime_binary_status=%s\n' "$runtime_binary_status"
    printf 'runtime_binary_produced=%s\n' "$runtime_binary_produced"
    printf 'integration_mode=%s\n' "$LIGHTTPD_INTEGRATION_MODE"
    printf 'runtime_smoke_verified=%s\n' "$runtime_smoke_verified"
    printf 'targeted_modsecurity_smoke_verified=%s\n' "$targeted_modsecurity_smoke_verified"
    printf 'targeted_modsecurity_smoke_blocked_missing_deps=%s\n' "$targeted_modsecurity_smoke_blocked_missing_deps"
    printf 'minimal_crs_smoke_verified=%s\n' "$minimal_crs_smoke_verified"
    printf 'minimal_crs_smoke_blocked_missing_crs=%s\n' "$minimal_crs_smoke_blocked_missing_crs"
    printf 'minimal_crs_smoke_blocked_missing_modsecurity=%s\n' "$minimal_crs_smoke_blocked_missing_modsecurity"
    printf 'minimal_crs_smoke_blocked_runtime=%s\n' "$minimal_crs_smoke_blocked_runtime"
    printf 'secondary_crs_smoke_verified=%s\n' "$secondary_crs_smoke_verified"
    printf 'secondary_crs_smoke_blocked_missing_crs=%s\n' "$secondary_crs_smoke_blocked_missing_crs"
    printf 'secondary_crs_smoke_blocked_missing_modsecurity=%s\n' "$secondary_crs_smoke_blocked_missing_modsecurity"
    printf 'secondary_crs_smoke_blocked_runtime=%s\n' "$secondary_crs_smoke_blocked_runtime"
    printf 'secondary_crs_probe_not_blocked=%s\n' "$secondary_crs_probe_not_blocked"
    printf 'secondary_crs_rule_id=%s\n' "$secondary_crs_rule_id"
    printf 'secondary_crs_rule_message=%s\n' "$secondary_crs_rule_message"
    printf 'secondary_crs_evidence=%s\n' "$secondary_crs_evidence"
    printf 'secondary_crs_status=%s\n' "$secondary_crs_status"
    printf 'crs_source_dir=%s\n' "$crs_source_dir"
    printf 'crs_git_ref=%s\n' "$crs_git_ref"
    printf 'crs_runtime_dir=%s\n' "$crs_runtime_dir"
    printf 'local_status=%s\n' "$local_status"
    printf 'enabled=%s\n' "$can_download"
    printf 'artifact_type=source_tarball\n'
    printf 'status=%s\n' "$component_status"
    printf '\n'
}

case "$MODE" in
    inventory|sources) ;;
    *)
        echo "usage: $0 [inventory|sources]" >&2
        exit 2
        ;;
esac

print_binary_component \
    envoy \
    "$ENVOY_VERSION" \
    "$ENVOY_SOURCE_URL" \
    "$ENVOY_INSTALL_DOCS_URL" \
    "$ENVOY_DOWNLOAD_URL" \
    "$ENVOY_SHA256" \
    "$ENVOY_SHA256_URL" \
    "$ENVOY_BIN" \
    "$ENVOY_INTEGRATION_MODE"

print_binary_component \
    traefik \
    "$TRAEFIK_VERSION" \
    "$TRAEFIK_SOURCE_URL" \
    "$TRAEFIK_INSTALL_DOCS_URL" \
    "$TRAEFIK_DOWNLOAD_URL" \
    "$TRAEFIK_SHA256" \
    "$TRAEFIK_SHA256_URL" \
    "$TRAEFIK_BIN" \
    "$TRAEFIK_INTEGRATION_MODE"

print_lighttpd_component
