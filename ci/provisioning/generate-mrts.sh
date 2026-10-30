#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
FRAMEWORK_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$FRAMEWORK_ROOT}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

MRTS_ROOT="${MRTS_ROOT:-$FRAMEWORK_ROOT/tools/MRTS}"
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
MRTS_BUILD_ROOT="${MRTS_BUILD_ROOT:-$BUILD_ROOT/mrts}"
MRTS_CORPUS="${MRTS_CORPUS:-upstream-config-tests}"
MRTS_CORPUS_ROOT="$MRTS_BUILD_ROOT/$MRTS_CORPUS"
case "$MRTS_CORPUS" in
    feature-demo)
        MRTS_DEFINITIONS="${MRTS_DEFINITIONS:-$MRTS_ROOT/feature_demo/config_tests}"
        ;;
    *)
        MRTS_DEFINITIONS="${MRTS_DEFINITIONS:-$MRTS_ROOT/config_tests}"
        ;;
esac
MRTS_RULES_OUT="${MRTS_RULES_OUT:-$MRTS_CORPUS_ROOT/rules}"
MRTS_FTW_OUT="${MRTS_FTW_OUT:-$MRTS_CORPUS_ROOT/ftw}"
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export PYTHONDONTWRITEBYTECODE

if [ ! -d "$MRTS_ROOT" ]; then
    echo "BLOCKED: MRTS_ROOT missing: $MRTS_ROOT" >&2
    exit 77
fi

if [ ! -f "$MRTS_ROOT/mrts/generate-rules.py" ]; then
    echo "BLOCKED: MRTS generator missing: $MRTS_ROOT/mrts/generate-rules.py" >&2
    exit 77
fi

assert_safe_runtime_path "$MRTS_BUILD_ROOT" MRTS_BUILD_ROOT || exit 77
assert_runtime_path_under_root "$MRTS_BUILD_ROOT" "$BUILD_ROOT/mrts" MRTS_BUILD_ROOT || exit 77
assert_safe_runtime_path "$MRTS_RULES_OUT" MRTS_RULES_OUT || exit 77
assert_runtime_path_under_root "$MRTS_RULES_OUT" "$MRTS_BUILD_ROOT" MRTS_RULES_OUT || exit 77
assert_safe_runtime_path "$MRTS_FTW_OUT" MRTS_FTW_OUT || exit 77
assert_runtime_path_under_root "$MRTS_FTW_OUT" "$MRTS_BUILD_ROOT" MRTS_FTW_OUT || exit 77
mkdir -p "$MRTS_RULES_OUT" "$MRTS_FTW_OUT"
find "$MRTS_RULES_OUT" -type f -name '*.conf' -exec rm -f {} \;
find "$MRTS_FTW_OUT" -type f -name '*.yaml' -exec rm -f {} \;

(
    cd "$MRTS_ROOT"
    "${PYTHON:-python3}" "$SCRIPT_DIR/mrts_definition_guard.py" \
        --generator "$MRTS_ROOT/mrts/generate-rules.py" \
        --snapshot-root "$MRTS_BUILD_ROOT" \
        --rules-out "$MRTS_RULES_OUT" \
        --tests-out "$MRTS_FTW_OUT" \
        --definition-directories "$MRTS_DEFINITIONS"
)

rule_count=$(find "$MRTS_RULES_OUT" -type f -name '*.conf' | wc -l | tr -d ' ')
ftw_count=$(find "$MRTS_FTW_OUT" -type f -name '*.yaml' | wc -l | tr -d ' ')

echo "MRTS generation complete"
echo "Corpus: $MRTS_CORPUS"
echo "Definition directories: $MRTS_DEFINITIONS"
echo "Rules: $rule_count ($MRTS_RULES_OUT)"
echo "FTW tests: $ftw_count ($MRTS_FTW_OUT)"
