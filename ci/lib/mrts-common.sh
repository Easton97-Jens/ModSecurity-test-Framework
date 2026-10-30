#!/bin/sh
# Shared MRTS helper functions.
#
# This file is intentionally sourceable. It defines defaults and functions only;
# callers choose whether to enable set -e/set -u.

FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(pwd)}"
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
VERIFIED_TMP_ROOT="${VERIFIED_TMP_ROOT:-$VERIFIED_RUN_ROOT/tmp}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
TMP_ROOT="${TMP_ROOT:-$VERIFIED_TMP_ROOT}"
MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-no-crs}"
MODSECURITY_MRTS_VARIANT="${MODSECURITY_MRTS_VARIANT:-no-mrts}"
MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="${MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO:-0}"
MODSECURITY_MRTS_PREPARED="${MODSECURITY_MRTS_PREPARED:-0}"
MRTS_ROOT="${MRTS_ROOT:-$FRAMEWORK_ROOT/tools/MRTS}"
MRTS_BUILD_ROOT="${MRTS_BUILD_ROOT:-$BUILD_ROOT/mrts}"
# Readiness belongs to this shell. Children verify the manifest and create their
# own materialization instead of inheriting another connector's writable files.
MRTS_RUNTIME_READY=0
MRTS_PACKAGE_READY=0
case "${MRTS_BASE_INPUTS_CAPTURED:-0}" in
    1) : ;;
    *)
        MRTS_BASE_RULE_PREAMBLE_FILE="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
        MRTS_BASE_EXTRA_CASE_ROOTS="${EXTRA_CASE_ROOTS:-}"
        MRTS_BASE_INPUTS_CAPTURED=1
        export MRTS_BASE_RULE_PREAMBLE_FILE MRTS_BASE_EXTRA_CASE_ROOTS MRTS_BASE_INPUTS_CAPTURED
        ;;
esac

MRTS_CONFIG_TESTS="${MRTS_CONFIG_TESTS:-$MRTS_ROOT/config_tests}"
MRTS_GOLDEN_TESTS="${MRTS_GOLDEN_TESTS:-$MRTS_ROOT/generated/tests/regression/tests}"
MRTS_GOLDEN_RULES="${MRTS_GOLDEN_RULES:-$MRTS_ROOT/generated/rules}"
MRTS_FEATURE_DEMO_CONFIG_TESTS="${MRTS_FEATURE_DEMO_CONFIG_TESTS:-$MRTS_ROOT/feature_demo/config_tests}"
MRTS_FEATURE_DEMO_GOLDEN_TESTS="${MRTS_FEATURE_DEMO_GOLDEN_TESTS:-$MRTS_ROOT/feature_demo/generated/tests}"
MRTS_FEATURE_DEMO_GOLDEN_RULES="${MRTS_FEATURE_DEMO_GOLDEN_RULES:-$MRTS_ROOT/feature_demo/generated/rules}"

MRTS_UPSTREAM_ROOT="$MRTS_BUILD_ROOT/upstream-config-tests"
MRTS_FEATURE_DEMO_ROOT="$MRTS_BUILD_ROOT/feature-demo"
MRTS_CASE_ROOT="${MRTS_CASE_ROOT:-$MRTS_UPSTREAM_ROOT/framework-cases}"
MRTS_UPSTREAM_CASE_ROOT="$MRTS_UPSTREAM_ROOT/framework-cases"
MRTS_FEATURE_DEMO_CASE_ROOT="$MRTS_FEATURE_DEMO_ROOT/framework-cases"
MRTS_UPSTREAM_DEFINITIONS="${MRTS_UPSTREAM_DEFINITIONS:-$MRTS_CONFIG_TESTS}"
MRTS_FEATURE_DEMO_DEFINITIONS="${MRTS_FEATURE_DEMO_DEFINITIONS:-$MRTS_FEATURE_DEMO_CONFIG_TESTS}"
MRTS_UPSTREAM_RULES_OUT="$MRTS_UPSTREAM_ROOT/rules"
MRTS_UPSTREAM_FTW_OUT="$MRTS_UPSTREAM_ROOT/ftw"
MRTS_UPSTREAM_LOAD_FILE="$MRTS_UPSTREAM_ROOT/mrts.load"
MRTS_FEATURE_DEMO_RULES_OUT="$MRTS_FEATURE_DEMO_ROOT/rules"
MRTS_FEATURE_DEMO_FTW_OUT="$MRTS_FEATURE_DEMO_ROOT/ftw"
MRTS_FEATURE_DEMO_LOAD_FILE="$MRTS_FEATURE_DEMO_ROOT/mrts.load"

validate_mrts_variant() {
    case "$MODSECURITY_MRTS_VARIANT" in
        no-mrts|with-mrts)
            ;;
        *)
            printf '%s\n' "ERROR: invalid MODSECURITY_MRTS_VARIANT=$MODSECURITY_MRTS_VARIANT" >&2
            exit 2
            ;;
    esac
    return 0
}

mrts_append_extra_case_root() {
    new_root=$1
    case "$(CDPATH='' cd "$new_root" 2>/dev/null && pwd || printf '%s' "$new_root")" in
        "$MRTS_ROOT"/generated|"$MRTS_ROOT"/generated/*|"$MRTS_ROOT"/feature_demo/generated|"$MRTS_ROOT"/feature_demo/generated/*)
            echo "ERROR: refusing to add MRTS golden references as case roots: $new_root" >&2
            exit 2
            ;;
        *)
            ;;
    esac
    case ":${EXTRA_CASE_ROOTS:-}:" in
        *:"$new_root":*)
            ;;
        *)
            case "${EXTRA_CASE_ROOTS:-}" in
                "")
                    EXTRA_CASE_ROOTS="$new_root"
                    ;;
                *)
                    EXTRA_CASE_ROOTS="${EXTRA_CASE_ROOTS}:$new_root"
                    ;;
            esac
            ;;
    esac
    export EXTRA_CASE_ROOTS
    return $?
}

mrts_append_reference_case_root() {
    new_root=$1
    case "$(CDPATH='' cd "$new_root" 2>/dev/null && pwd || printf '%s' "$new_root")" in
        "$MRTS_ROOT"/generated|"$MRTS_ROOT"/generated/*|"$MRTS_ROOT"/feature_demo/generated|"$MRTS_ROOT"/feature_demo/generated/*)
            echo "ERROR: refusing to add MRTS golden references as reference case roots: $new_root" >&2
            exit 2
            ;;
        *)
            ;;
    esac
    case ":${REFERENCE_CASE_ROOTS:-}:" in
        *:"$new_root":*)
            ;;
        *)
            case "${REFERENCE_CASE_ROOTS:-}" in
                "")
                    REFERENCE_CASE_ROOTS="$new_root"
                    ;;
                *)
                    REFERENCE_CASE_ROOTS="${REFERENCE_CASE_ROOTS}:$new_root"
                    ;;
            esac
            ;;
    esac
    export REFERENCE_CASE_ROOTS
    return $?
}

mrts_generate_upstream() {
    MRTS_CORPUS=upstream-config-tests \
    MRTS_DEFINITIONS="$MRTS_UPSTREAM_DEFINITIONS" \
    MRTS_RULES_OUT="$MRTS_UPSTREAM_RULES_OUT" \
    MRTS_FTW_OUT="$MRTS_UPSTREAM_FTW_OUT" \
        sh "$FRAMEWORK_ROOT/ci/provisioning/generate-mrts.sh"
    return $?
}

mrts_generate_feature_demo() {
    MRTS_CORPUS=feature-demo \
    MRTS_DEFINITIONS="$MRTS_FEATURE_DEMO_DEFINITIONS" \
    MRTS_RULES_OUT="$MRTS_FEATURE_DEMO_RULES_OUT" \
    MRTS_FTW_OUT="$MRTS_FEATURE_DEMO_FTW_OUT" \
        sh "$FRAMEWORK_ROOT/ci/provisioning/generate-mrts.sh"
    return $?
}

# Compatibility entry points all use the same validated package producer.
mrts_package_command() {
    mrts_package_action=$1
    shift
    "${PYTHON:-python3}" "$FRAMEWORK_ROOT/ci/provisioning/mrts-package.py" \
        "$mrts_package_action" \
        --framework-root "$FRAMEWORK_ROOT" --mrts-root "$MRTS_ROOT" \
        --connector-root "${CONNECTOR_ROOT:-$FRAMEWORK_ROOT}" \
        --build-root "$BUILD_ROOT" --package-root "$MRTS_PACKAGE_ROOT" \
        --include-feature-demo "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" \
        --upstream-definitions "$MRTS_UPSTREAM_DEFINITIONS" \
        --feature-demo-definitions "$MRTS_FEATURE_DEMO_DEFINITIONS" "$@"
    return $?
}

mrts_bind_package_paths() {
    MRTS_UPSTREAM_ROOT="$1/upstream-config-tests"
    MRTS_FEATURE_DEMO_ROOT="$1/feature-demo"
    MRTS_UPSTREAM_RULES_OUT="$MRTS_UPSTREAM_ROOT/rules"
    MRTS_UPSTREAM_FTW_OUT="$MRTS_UPSTREAM_ROOT/ftw"
    MRTS_UPSTREAM_CASE_ROOT="$MRTS_UPSTREAM_ROOT/framework-cases"
    MRTS_UPSTREAM_LOAD_FILE="$MRTS_UPSTREAM_ROOT/mrts.load"
    MRTS_FEATURE_DEMO_RULES_OUT="$MRTS_FEATURE_DEMO_ROOT/rules"
    MRTS_FEATURE_DEMO_FTW_OUT="$MRTS_FEATURE_DEMO_ROOT/ftw"
    MRTS_FEATURE_DEMO_CASE_ROOT="$MRTS_FEATURE_DEMO_ROOT/framework-cases"
    MRTS_FEATURE_DEMO_LOAD_FILE="$MRTS_FEATURE_DEMO_ROOT/mrts.load"
    MRTS_LOAD_FILE="$MRTS_UPSTREAM_LOAD_FILE"
    MRTS_CASE_ROOT="$MRTS_UPSTREAM_CASE_ROOT"
    export MRTS_LOAD_FILE MRTS_CASE_ROOT
    return 0
}

mrts_generate_all_corpora() {
    case "${MRTS_PACKAGE_READY:-0}:$MODSECURITY_MRTS_PREPARED" in
        1:*|*:1)
            case "${MRTS_PACKAGE_ROOT:-}" in
                "") echo "BLOCKED: prepared MRTS requires MRTS_PACKAGE_ROOT and a validated manifest" >&2; return 77 ;;
                *) : ;;
            esac
            mrts_package_command verify >/dev/null || return $?
            ;;
        *)
            case "${MRTS_PACKAGE_ROOT:-}" in
                "")
                    assert_safe_runtime_path "$MRTS_BUILD_ROOT" MRTS_BUILD_ROOT || return 77
                    mkdir -p "$MRTS_BUILD_ROOT" || return $?
                    mrts_package_parent=$(mktemp -d "$MRTS_BUILD_ROOT/preparation.XXXXXX") || return $?
                    MRTS_PACKAGE_ROOT="$mrts_package_parent/package"
                    ;;
                *) : ;;
            esac
            mrts_package_command prepare >/dev/null || return $?
            ;;
    esac
    MRTS_PACKAGE_READY=1
    MODSECURITY_MRTS_PREPARED=1
    export MRTS_PACKAGE_ROOT MODSECURITY_MRTS_PREPARED
    case "${MRTS_RUNTIME_READY:-0}" in
        1) : ;;
        *) mrts_bind_package_paths "$MRTS_PACKAGE_ROOT" || return $? ;;
    esac
    return 0
}

mrts_rule_ids() {
    rules_dir=$1
    find "$rules_dir" -type f -name '*.conf' 2>/dev/null | sort | while IFS= read -r rule_file; do
        sed -n 's/.*id:\([0-9][0-9]*\).*/\1/p' "$rule_file"
    done | sort -u
    return $?
}

mrts_path_matches() (
    mrts_path_matches_path=$1
    mrts_path_matches_kind=$2
    case "$mrts_path_matches_path" in
        -*)
            mrts_path_matches_path="./$mrts_path_matches_path"
            ;;
        *)
            :
            ;;
    esac
    case "$mrts_path_matches_kind" in
        regular)
            mrts_path_matches_result=$(command -p find -H "$mrts_path_matches_path" -prune -type f -print 2>/dev/null)
            ;;
        directory)
            mrts_path_matches_result=$(command -p find -H "$mrts_path_matches_path" -prune -type d -print 2>/dev/null)
            ;;
        nonempty)
            mrts_path_matches_result=$(command -p find -H "$mrts_path_matches_path" -prune -size +0c -print 2>/dev/null)
            ;;
        *)
            return 2
            ;;
    esac
    mrts_path_matches_status=$?
    case "$mrts_path_matches_status" in
        0)
            case "$mrts_path_matches_result" in
                "")
                    mrts_path_matches_status=1
                    ;;
                *)
                    mrts_path_matches_status=0
                    ;;
            esac
            ;;
        *)
            mrts_path_matches_status=2
            ;;
    esac
    return "$mrts_path_matches_status"
)

mrts_check_feature_demo_runtime_safe() {
    tmp_dir="${TMP_ROOT:-$BUILD_ROOT/tmp}"
    assert_safe_runtime_path "$tmp_dir" MRTS_TMP_ROOT || exit 77
    mkdir -p "$tmp_dir"
    upstream_ids="$tmp_dir/mrts-upstream-rule-ids.$$"
    feature_ids="$tmp_dir/mrts-feature-demo-rule-ids.$$"
    duplicate_ids="$tmp_dir/mrts-feature-demo-duplicate-rule-ids.$$"
    mrts_rule_ids "$MRTS_UPSTREAM_RULES_OUT" > "$upstream_ids"
    mrts_rule_ids "$MRTS_FEATURE_DEMO_RULES_OUT" > "$feature_ids"
    comm -12 "$upstream_ids" "$feature_ids" > "$duplicate_ids" || true
    if mrts_path_matches "$duplicate_ids" nonempty; then
        echo "BLOCKED: feature-demo MRTS runtime has duplicate rule IDs with upstream-config-tests: $(tr '\n' ' ' < "$duplicate_ids")" >&2
        rm -f "$upstream_ids" "$feature_ids" "$duplicate_ids"
        exit 77
    else
        duplicate_status=$?
        case "$duplicate_status" in
            1)
                ;;
            *)
                echo "BLOCKED: cannot inspect feature-demo MRTS duplicate rule IDs: $duplicate_ids" >&2
                rm -f "$upstream_ids" "$feature_ids" "$duplicate_ids"
                exit 77
                ;;
        esac
    fi
    rm -f "$upstream_ids" "$feature_ids" "$duplicate_ids"
    return $?
}

mrts_append_rule_preamble() {
    new_preamble=$1
    existing_preamble="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
    case "$existing_preamble" in
        "")
            MODSECURITY_RULE_PREAMBLE_FILE="$new_preamble"
            export MODSECURITY_RULE_PREAMBLE_FILE
            return 0
            ;;
        "$new_preamble")
            MODSECURITY_RULE_PREAMBLE_FILE="$new_preamble"
            export MODSECURITY_RULE_PREAMBLE_FILE
            return 0
            ;;
        *)
            :
            ;;
    esac

    assert_safe_runtime_path "$BUILD_ROOT/preambles" MRTS_PREAMBLE_DIR || return 77
    mkdir -p "$BUILD_ROOT/preambles" || return $?
    combined=$(mktemp "$BUILD_ROOT/preambles/mrts-combined.XXXXXX.load") || return $?
    assert_not_system_path_for_write "$combined" MRTS_COMBINED_PREAMBLE || return 77
    if ! {
        printf 'Include "%s"\n' "$existing_preamble" &&
        printf 'Include "%s"\n' "$new_preamble"
    } > "$combined"; then
        rm -f "$combined"
        return 77
    fi
    MODSECURITY_RULE_PREAMBLE_FILE="$combined"
    export MODSECURITY_RULE_PREAMBLE_FILE
    return 0
}

mrts_import_cases() {
    # Import is transactional and already included in package preparation.
    mrts_generate_all_corpora || return $?
    return 0
}

prepare_mrts_variant() {
    validate_mrts_variant || return $?
    case "$MODSECURITY_MRTS_VARIANT" in
        no-mrts) return 0 ;;
        *) : ;;
    esac
    mrts_generate_all_corpora || return $?
    # A runner receives a private materialization, even if a prepared shared
    # package was supplied. Repeated calls in this shell reuse only that copy.
    case "${MRTS_RUNTIME_READY:-0}" in
        1) return 0 ;;
        *) : ;;
    esac
    mrts_private_parent=$(mktemp -d "$MRTS_BUILD_ROOT/runtime.XXXXXX") || return $?
    MRTS_RUNTIME_ROOT="$mrts_private_parent/package"
    mrts_package_command materialize --output-root "$MRTS_RUNTIME_ROOT" \
        --port "${MRTS_RUNTIME_PORT:-80}" >/dev/null || return $?
    mrts_bind_package_paths "$MRTS_RUNTIME_ROOT" || return $?
    MODSECURITY_RULE_PREAMBLE_FILE="$MRTS_BASE_RULE_PREAMBLE_FILE"
    EXTRA_CASE_ROOTS="$MRTS_BASE_EXTRA_CASE_ROOTS"
    mrts_append_rule_preamble "$MRTS_LOAD_FILE" || return $?
    mrts_append_extra_case_root "$MRTS_UPSTREAM_CASE_ROOT" || return $?
    case "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" in
        1)
            mrts_append_rule_preamble "$MRTS_FEATURE_DEMO_LOAD_FILE" || return $?
            mrts_append_extra_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT" || return $?
            ;;
        0) : ;;
        *) echo "BLOCKED: demo selection must be 0 or 1" >&2; return 77 ;;
    esac
    MRTS_RUNTIME_READY=1
    export MRTS_RUNTIME_ROOT
    return 0
}

prepare_mrts_runtime_variant() {
    prepare_mrts_variant || return $?
    return 0
}

set_mrts_results_dir() {
    case "${RESULTS_DIR:-}" in
        "")
            ;;
        *)
            export RESULTS_DIR
            return 0
            ;;
    esac

    MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-no-crs}"
    MODSECURITY_MRTS_VARIANT="${MODSECURITY_MRTS_VARIANT:-no-mrts}"
    VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
    VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
    BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
    RESULTS_DIR="$BUILD_ROOT/results/$MODSECURITY_TEST_VARIANT/$MODSECURITY_MRTS_VARIANT"
    export BUILD_ROOT RESULTS_DIR
    return $?
}
