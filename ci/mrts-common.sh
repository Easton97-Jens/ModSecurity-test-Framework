# Shared MRTS helper functions.
#
# This file is intentionally sourceable. It defines defaults and functions only;
# callers choose whether to enable set -e/set -u.

FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(pwd)}"
BUILD_ROOT="${BUILD_ROOT:-$FRAMEWORK_ROOT/build}"
MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-no-crs}"
MODSECURITY_MRTS_VARIANT="${MODSECURITY_MRTS_VARIANT:-no-mrts}"
MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="${MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO:-0}"
MODSECURITY_MRTS_PREPARED="${MODSECURITY_MRTS_PREPARED:-0}"
MRTS_CASE_ROOT="${MRTS_CASE_ROOT:-$FRAMEWORK_ROOT/tests/mrts/generated/framework-cases}"
MRTS_UPSTREAM_CASE_ROOT="$MRTS_CASE_ROOT/upstream-config-tests"
MRTS_FEATURE_DEMO_CASE_ROOT="$MRTS_CASE_ROOT/feature-demo"
MRTS_UPSTREAM_DEFINITIONS="$FRAMEWORK_ROOT/tests/mrts/definitions/upstream-config-tests"
MRTS_FEATURE_DEMO_DEFINITIONS="$FRAMEWORK_ROOT/tests/mrts/definitions/feature-demo-config-tests"
MRTS_UPSTREAM_RULES_OUT="$FRAMEWORK_ROOT/tests/mrts/generated/rules"
MRTS_UPSTREAM_FTW_OUT="$FRAMEWORK_ROOT/tests/mrts/generated/ftw"
MRTS_FEATURE_DEMO_RULES_OUT="$FRAMEWORK_ROOT/tests/mrts/generated/feature-demo/rules"
MRTS_FEATURE_DEMO_FTW_OUT="$FRAMEWORK_ROOT/tests/mrts/generated/feature-demo/ftw"
MRTS_UPSTREAM_GOLDEN_TESTS="$FRAMEWORK_ROOT/tests/mrts/imported/upstream-generated-tests"
MRTS_FEATURE_DEMO_GOLDEN_TESTS="$FRAMEWORK_ROOT/tests/mrts/imported/feature-demo-generated-tests"

validate_mrts_variant() {
    case "$MODSECURITY_MRTS_VARIANT" in
        no-mrts|with-mrts)
            return 0
            ;;
        *)
            echo "ERROR: invalid MODSECURITY_MRTS_VARIANT=$MODSECURITY_MRTS_VARIANT"
            exit 2
            ;;
    esac
}

mrts_append_extra_case_root() {
    new_root=$1
    case "$(CDPATH= cd "$new_root" 2>/dev/null && pwd || printf '%s' "$new_root")" in
        "$FRAMEWORK_ROOT"/tests/mrts/imported|"$FRAMEWORK_ROOT"/tests/mrts/imported/*)
            echo "ERROR: refusing to add MRTS golden references as case roots: $new_root" >&2
            exit 2
            ;;
    esac
    case ":${EXTRA_CASE_ROOTS:-}:" in
        *:"$new_root":*)
            ;;
        *)
            if [ -n "${EXTRA_CASE_ROOTS:-}" ]; then
                EXTRA_CASE_ROOTS="${EXTRA_CASE_ROOTS}:$new_root"
            else
                EXTRA_CASE_ROOTS="$new_root"
            fi
            ;;
    esac
    export EXTRA_CASE_ROOTS
}

mrts_append_reference_case_root() {
    new_root=$1
    case "$(CDPATH= cd "$new_root" 2>/dev/null && pwd || printf '%s' "$new_root")" in
        "$FRAMEWORK_ROOT"/tests/mrts/imported|"$FRAMEWORK_ROOT"/tests/mrts/imported/*)
            echo "ERROR: refusing to add MRTS golden references as reference case roots: $new_root" >&2
            exit 2
            ;;
    esac
    case ":${REFERENCE_CASE_ROOTS:-}:" in
        *:"$new_root":*)
            ;;
        *)
            if [ -n "${REFERENCE_CASE_ROOTS:-}" ]; then
                REFERENCE_CASE_ROOTS="${REFERENCE_CASE_ROOTS}:$new_root"
            else
                REFERENCE_CASE_ROOTS="$new_root"
            fi
            ;;
    esac
    export REFERENCE_CASE_ROOTS
}

mrts_generate_upstream() {
    MRTS_CORPUS=upstream-config-tests \
    MRTS_DEFINITIONS="$MRTS_UPSTREAM_DEFINITIONS" \
    MRTS_RULES_OUT="$MRTS_UPSTREAM_RULES_OUT" \
    MRTS_FTW_OUT="$MRTS_UPSTREAM_FTW_OUT" \
        sh "$FRAMEWORK_ROOT/ci/generate-mrts.sh"
}

mrts_generate_feature_demo() {
    MRTS_CORPUS=feature-demo \
    MRTS_DEFINITIONS="$MRTS_FEATURE_DEMO_DEFINITIONS" \
    MRTS_RULES_OUT="$MRTS_FEATURE_DEMO_RULES_OUT" \
    MRTS_FTW_OUT="$MRTS_FEATURE_DEMO_FTW_OUT" \
        sh "$FRAMEWORK_ROOT/ci/generate-mrts.sh"
}

mrts_generate_all_corpora() {
    mrts_generate_upstream
    mrts_generate_feature_demo
}

mrts_rule_ids() {
    rules_dir=$1
    find "$rules_dir" -type f -name '*.conf' 2>/dev/null | sort | while IFS= read -r rule_file; do
        sed -n 's/.*id:\([0-9][0-9]*\).*/\1/p' "$rule_file"
    done | sort -u
}

mrts_check_feature_demo_runtime_safe() {
    tmp_dir="${TMP_ROOT:-$BUILD_ROOT/tmp}"
    mkdir -p "$tmp_dir"
    upstream_ids="$tmp_dir/mrts-upstream-rule-ids.$$"
    feature_ids="$tmp_dir/mrts-feature-demo-rule-ids.$$"
    duplicate_ids="$tmp_dir/mrts-feature-demo-duplicate-rule-ids.$$"
    mrts_rule_ids "$MRTS_UPSTREAM_RULES_OUT" > "$upstream_ids"
    mrts_rule_ids "$MRTS_FEATURE_DEMO_RULES_OUT" > "$feature_ids"
    comm -12 "$upstream_ids" "$feature_ids" > "$duplicate_ids" || true
    if [ -s "$duplicate_ids" ]; then
        echo "BLOCKED: feature-demo MRTS runtime has duplicate rule IDs with upstream-config-tests: $(tr '\n' ' ' < "$duplicate_ids")" >&2
        rm -f "$upstream_ids" "$feature_ids" "$duplicate_ids"
        exit 77
    fi
    rm -f "$upstream_ids" "$feature_ids" "$duplicate_ids"
}

mrts_append_rule_preamble() {
    new_preamble=$1
    existing_preamble="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
    if [ -z "$existing_preamble" ] || [ "$existing_preamble" = "$new_preamble" ]; then
        MODSECURITY_RULE_PREAMBLE_FILE="$new_preamble"
        export MODSECURITY_RULE_PREAMBLE_FILE
        return 0
    fi

    mkdir -p "$BUILD_ROOT/preambles"
    combined="$BUILD_ROOT/preambles/mrts-combined.load"
    {
        printf 'Include "%s"\n' "$existing_preamble"
        printf 'Include "%s"\n' "$new_preamble"
    } > "$combined"
    MODSECURITY_RULE_PREAMBLE_FILE="$combined"
    export MODSECURITY_RULE_PREAMBLE_FILE
}

mrts_import_cases() {
    MRTS_CASE_ROOT="${MRTS_CASE_ROOT:-$FRAMEWORK_ROOT/tests/mrts/generated/framework-cases}"
    MRTS_UPSTREAM_CASE_ROOT="$MRTS_CASE_ROOT/upstream-config-tests"
    MRTS_FEATURE_DEMO_CASE_ROOT="$MRTS_CASE_ROOT/feature-demo"
    mkdir -p "$MRTS_UPSTREAM_CASE_ROOT" "$MRTS_FEATURE_DEMO_CASE_ROOT"
    find "$MRTS_CASE_ROOT" -type f -name '*.yaml' -exec rm -f {} \;
    "${PYTHON:-python3}" "$FRAMEWORK_ROOT/ci/import-mrts-cases.py" \
        --framework-root "$FRAMEWORK_ROOT" \
        --mrts-corpus upstream-config-tests \
        --source-definition-dir "$MRTS_UPSTREAM_DEFINITIONS" \
        --upstream-ftw-dir "$MRTS_UPSTREAM_GOLDEN_TESTS" \
        --mrts-ftw-dir "$MRTS_UPSTREAM_FTW_OUT" \
        --mrts-rules-dir "$MRTS_UPSTREAM_RULES_OUT" \
        --output-dir "$MRTS_UPSTREAM_CASE_ROOT"
    feature_status=pending
    feature_reason="MRTS feature-demo corpus is optional/demo and not part of default runtime."
    if [ "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1" ]; then
        mrts_check_feature_demo_runtime_safe
        feature_status=computed
        feature_reason=""
    fi
    "${PYTHON:-python3}" "$FRAMEWORK_ROOT/ci/import-mrts-cases.py" \
        --framework-root "$FRAMEWORK_ROOT" \
        --mrts-corpus feature-demo \
        --source-definition-dir "$MRTS_FEATURE_DEMO_DEFINITIONS" \
        --upstream-ftw-dir "$MRTS_FEATURE_DEMO_GOLDEN_TESTS" \
        --mrts-ftw-dir "$MRTS_FEATURE_DEMO_FTW_OUT" \
        --mrts-rules-dir "$MRTS_FEATURE_DEMO_RULES_OUT" \
        --output-dir "$MRTS_FEATURE_DEMO_CASE_ROOT" \
        --case-status "$feature_status" \
        --pending-reason "$feature_reason"
}

prepare_mrts_variant() {
    validate_mrts_variant
    if [ "$MODSECURITY_MRTS_VARIANT" = "no-mrts" ]; then
        if [ -n "${EXTRA_CASE_ROOTS:-}" ]; then
            export EXTRA_CASE_ROOTS
        fi
        return 0
    fi

    if [ "$MODSECURITY_MRTS_PREPARED" = "1" ]; then
        MRTS_LOAD_FILE="${MRTS_LOAD_FILE:-$FRAMEWORK_ROOT/tests/mrts/generated/mrts.load}"
        if [ ! -f "$MRTS_LOAD_FILE" ]; then
            echo "BLOCKED: prepared MRTS load file missing: $MRTS_LOAD_FILE" >&2
            exit 77
        fi
        if [ ! -d "$MRTS_UPSTREAM_CASE_ROOT" ]; then
            echo "BLOCKED: prepared MRTS case root missing: $MRTS_UPSTREAM_CASE_ROOT" >&2
            exit 77
        fi
        mrts_append_rule_preamble "$MRTS_LOAD_FILE"
        mrts_append_extra_case_root "$MRTS_UPSTREAM_CASE_ROOT"
        mrts_append_reference_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
        if [ "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1" ]; then
            MRTS_FEATURE_DEMO_LOAD_FILE="${MRTS_FEATURE_DEMO_LOAD_FILE:-$FRAMEWORK_ROOT/tests/mrts/generated/feature-demo/mrts.load}"
            if [ ! -f "$MRTS_FEATURE_DEMO_LOAD_FILE" ]; then
                echo "BLOCKED: prepared feature-demo MRTS load file missing: $MRTS_FEATURE_DEMO_LOAD_FILE" >&2
                exit 77
            fi
            mrts_append_rule_preamble "$MRTS_FEATURE_DEMO_LOAD_FILE"
            mrts_append_extra_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
        fi
        return 0
    fi

    mrts_generate_all_corpora
    MRTS_LOAD_FILE=$(MRTS_RULES_OUT="$MRTS_UPSTREAM_RULES_OUT" sh "$FRAMEWORK_ROOT/ci/write-mrts-load.sh")
    mrts_append_rule_preamble "$MRTS_LOAD_FILE"
    if [ "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1" ]; then
        mrts_check_feature_demo_runtime_safe
        MRTS_FEATURE_DEMO_LOAD_FILE=$(MRTS_RULES_OUT="$MRTS_FEATURE_DEMO_RULES_OUT" MRTS_LOAD_FILE="$FRAMEWORK_ROOT/tests/mrts/generated/feature-demo/mrts.load" sh "$FRAMEWORK_ROOT/ci/write-mrts-load.sh")
        mrts_append_rule_preamble "$MRTS_FEATURE_DEMO_LOAD_FILE"
    fi
    mrts_append_extra_case_root "$MRTS_UPSTREAM_CASE_ROOT"
    mrts_append_reference_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
    if [ "$MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO" = "1" ]; then
        mrts_append_extra_case_root "$MRTS_FEATURE_DEMO_CASE_ROOT"
    fi
}

prepare_mrts_runtime_variant() {
    prepare_mrts_variant
    if [ "$MODSECURITY_MRTS_VARIANT" = "with-mrts" ] && [ "$MODSECURITY_MRTS_PREPARED" != "1" ]; then
        mrts_import_cases
    fi
}

set_mrts_results_dir() {
    if [ -n "${RESULTS_DIR:-}" ]; then
        export RESULTS_DIR
        return 0
    fi

    MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-no-crs}"
    MODSECURITY_MRTS_VARIANT="${MODSECURITY_MRTS_VARIANT:-no-mrts}"
    BUILD_ROOT="${BUILD_ROOT:-$FRAMEWORK_ROOT/build}"
    RESULTS_DIR="$BUILD_ROOT/results/$MODSECURITY_TEST_VARIANT/$MODSECURITY_MRTS_VARIANT"
    export BUILD_ROOT RESULTS_DIR
}
