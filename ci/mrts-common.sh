# Shared MRTS helper functions.
#
# This file is intentionally sourceable. It defines defaults and functions only;
# callers choose whether to enable set -e/set -u.

FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(pwd)}"
BUILD_ROOT="${BUILD_ROOT:-$FRAMEWORK_ROOT/build}"
MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-no-crs}"
MODSECURITY_MRTS_VARIANT="${MODSECURITY_MRTS_VARIANT:-no-mrts}"

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

prepare_mrts_variant() {
    validate_mrts_variant
    if [ "$MODSECURITY_MRTS_VARIANT" = "no-mrts" ]; then
        if [ -n "${EXTRA_CASE_ROOTS:-}" ]; then
            export EXTRA_CASE_ROOTS
        fi
        return 0
    fi

    sh "$FRAMEWORK_ROOT/ci/generate-mrts.sh"
    MRTS_LOAD_FILE=$(sh "$FRAMEWORK_ROOT/ci/write-mrts-load.sh")
    mrts_append_rule_preamble "$MRTS_LOAD_FILE"
    MRTS_CASE_ROOT="${MRTS_CASE_ROOT:-$FRAMEWORK_ROOT/tests/mrts/generated/framework-cases}"
    mrts_append_extra_case_root "$MRTS_CASE_ROOT"
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
