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
            if test -n "${EXTRA_CASE_ROOTS:-}"; then
                EXTRA_CASE_ROOTS="${EXTRA_CASE_ROOTS}:$new_root"
            else
                EXTRA_CASE_ROOTS="$new_root"
            fi
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
            if test -n "${REFERENCE_CASE_ROOTS:-}"; then
                REFERENCE_CASE_ROOTS="${REFERENCE_CASE_ROOTS}:$new_root"
            else
                REFERENCE_CASE_ROOTS="$new_root"
            fi
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

mrts_generate_all_corpora() {
    mrts_generate_upstream
    mrts_generate_feature_demo
    return $?
}

mrts_rule_ids() {
    rules_dir=$1
    find "$rules_dir" -type f -name '*.conf' 2>/dev/null | sort | while IFS= read -r rule_file; do
        sed -n 's/.*id:\([0-9][0-9]*\).*/\1/p' "$rule_file"
    done | sort -u
    return $?
}

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
    if test -s "$duplicate_ids"; then
        echo "BLOCKED: feature-demo MRTS runtime has duplicate rule IDs with upstream-config-tests: $(tr '\n' ' ' < "$duplicate_ids")" >&2
        rm -f "$upstream_ids" "$feature_ids" "$duplicate_ids"
        exit 77
    fi
    rm -f "$upstream_ids" "$feature_ids" "$duplicate_ids"
    return $?
}

mrts_append_rule_preamble() {
    new_preamble=$1
    existing_preamble="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
    if test -z "$existing_preamble" || test "$existing_preamble" = "$new_preamble"; then
        MODSECURITY_RULE_PREAMBLE_FILE="$new_preamble"
        export MODSECURITY_RULE_PREAMBLE_FILE
        return 0
    fi

    combined="$BUILD_ROOT/preambles/mrts-combined.load"
    assert_safe_runtime_path "$BUILD_ROOT/preambles" MRTS_PREAMBLE_DIR || exit 77
    assert_not_system_path_for_write "$combined" MRTS_COMBINED_PREAMBLE || exit 77
    mkdir -p "$BUILD_ROOT/preambles"
    {
        printf 'Include "%s"\n' "$existing_preamble"
        printf 'Include "%s"\n' "$new_preamble"
    } > "$combined"
    MODSECURITY_RULE_PREAMBLE_FILE="$combined"
    export MODSECURITY_RULE_PREAMBLE_FILE
    return $?
}

mrts_import_cases() {
    assert_safe_runtime_path "$MRTS_UPSTREAM_CASE_ROOT" MRTS_UPSTREAM_CASE_ROOT || exit 77
    assert_safe_runtime_path "$MRTS_FEATURE_DEMO_CASE_ROOT" MRTS_FEATURE_DEMO_CASE_ROOT || exit 77
    mkdir -p "$MRTS_UPSTREAM_CASE_ROOT" "$MRTS_FEATURE_DEMO_CASE_ROOT"
    find "$MRTS_UPSTREAM_CASE_ROOT" "$MRTS_FEATURE_DEMO_CASE_ROOT" -type f -name '*.yaml' -exec rm -f {} \;
    "${PYTHON:-python3}" "$FRAMEWORK_ROOT/ci/provisioning/import-mrts-cases.py" \
        --framework-root "$FRAMEWORK_ROOT" \
        --mrts-corpus upstream-config-tests \
        --source-definition-dir "$MRTS_UPSTREAM_DEFINITIONS" \
        --upstream-ftw-dir "$MRTS_GOLDEN_TESTS" \
        --mrts-ftw-dir "$MRTS_UPSTREAM_FTW_OUT" \
        --mrts-rules-dir "$MRTS_UPSTREAM_RULES_OUT" \
        --output-dir "$MRTS_UPSTREAM_CASE_ROOT"
    feature_status=pending
    feature_reason="MRTS feature-demo corpus is optional/demo and not part of default runtime."
    if test "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1"; then
        mrts_check_feature_demo_runtime_safe
        feature_status=computed
        feature_reason=""
    fi
    "${PYTHON:-python3}" "$FRAMEWORK_ROOT/ci/provisioning/import-mrts-cases.py" \
        --framework-root "$FRAMEWORK_ROOT" \
        --mrts-corpus feature-demo \
        --source-definition-dir "$MRTS_FEATURE_DEMO_DEFINITIONS" \
        --upstream-ftw-dir "$MRTS_FEATURE_DEMO_GOLDEN_TESTS" \
        --mrts-ftw-dir "$MRTS_FEATURE_DEMO_FTW_OUT" \
        --mrts-rules-dir "$MRTS_FEATURE_DEMO_RULES_OUT" \
        --output-dir "$MRTS_FEATURE_DEMO_CASE_ROOT" \
        --case-status "$feature_status" \
        --pending-reason "$feature_reason"
    return $?
}

prepare_mrts_variant() {
    validate_mrts_variant
    if test "$MODSECURITY_MRTS_VARIANT" = "no-mrts"; then
        if test -n "${EXTRA_CASE_ROOTS:-}"; then
            export EXTRA_CASE_ROOTS
        fi
        return 0
    fi

    if test "$MODSECURITY_MRTS_PREPARED" = "1"; then
        MRTS_LOAD_FILE="${MRTS_LOAD_FILE:-$MRTS_UPSTREAM_LOAD_FILE}"
        if test ! -f "$MRTS_LOAD_FILE"; then
            echo "BLOCKED: prepared MRTS load file missing: $MRTS_LOAD_FILE" >&2
            exit 77
        fi
        if test ! -d "$MRTS_UPSTREAM_CASE_ROOT"; then
            echo "BLOCKED: prepared MRTS case root missing: $MRTS_UPSTREAM_CASE_ROOT" >&2
            exit 77
        fi
        mrts_append_rule_preamble "$MRTS_LOAD_FILE"
        mrts_append_extra_case_root "$MRTS_UPSTREAM_CASE_ROOT"
        mrts_append_reference_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
        if test "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1"; then
            if test ! -f "$MRTS_FEATURE_DEMO_LOAD_FILE"; then
                echo "BLOCKED: prepared feature-demo MRTS load file missing: $MRTS_FEATURE_DEMO_LOAD_FILE" >&2
                exit 77
            fi
            mrts_append_rule_preamble "$MRTS_FEATURE_DEMO_LOAD_FILE"
            mrts_append_extra_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
        fi
        return 0
    fi

    mrts_generate_all_corpora
    MRTS_LOAD_FILE=$(MRTS_RULES_OUT="$MRTS_UPSTREAM_RULES_OUT" MRTS_LOAD_FILE="$MRTS_UPSTREAM_LOAD_FILE" sh "$FRAMEWORK_ROOT/ci/provisioning/write-mrts-load.sh")
    mrts_append_rule_preamble "$MRTS_LOAD_FILE"
    if test "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1"; then
        mrts_check_feature_demo_runtime_safe
        MRTS_FEATURE_DEMO_LOAD_FILE=$(MRTS_RULES_OUT="$MRTS_FEATURE_DEMO_RULES_OUT" MRTS_LOAD_FILE="$MRTS_FEATURE_DEMO_LOAD_FILE" sh "$FRAMEWORK_ROOT/ci/provisioning/write-mrts-load.sh")
        mrts_append_rule_preamble "$MRTS_FEATURE_DEMO_LOAD_FILE"
    fi
    mrts_append_extra_case_root "$MRTS_UPSTREAM_CASE_ROOT"
    mrts_append_reference_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
    if test "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1"; then
        mrts_append_extra_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
        return $?
    fi
    return 0
}

prepare_mrts_runtime_variant() {
    prepare_mrts_variant
    if test "$MODSECURITY_MRTS_VARIANT" = "with-mrts" && test "$MODSECURITY_MRTS_PREPARED" != "1"; then
        mrts_import_cases
        return $?
    fi
    return 0
}

set_mrts_results_dir() {
    if test -n "${RESULTS_DIR:-}"; then
        export RESULTS_DIR
        return 0
    fi

    MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-no-crs}"
    MODSECURITY_MRTS_VARIANT="${MODSECURITY_MRTS_VARIANT:-no-mrts}"
    VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
    VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
    BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
    RESULTS_DIR="$BUILD_ROOT/results/$MODSECURITY_TEST_VARIANT/$MODSECURITY_MRTS_VARIANT"
    export BUILD_ROOT RESULTS_DIR
    return $?
}
