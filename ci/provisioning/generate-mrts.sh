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

definition_dirs=$(printf '%s\n' "$MRTS_DEFINITIONS" | tr ':' '\n')
for definitions_dir in $definition_dirs; do
    if [ ! -d "$definitions_dir" ]; then
        echo "BLOCKED: MRTS definitions missing: $definitions_dir" >&2
        exit 77
    fi
done

definition_list=$(
    for definitions_dir in $definition_dirs; do
        if [ ! -d "$definitions_dir" ]; then
            echo "BLOCKED: MRTS definitions missing: $definitions_dir" >&2
            exit 77
        fi
        find "$definitions_dir" -type f -name '*.yaml'
    done
)
definition_list=$(printf '%s\n' "$definition_list" | sort)
if [ -z "$definition_list" ]; then
    echo "BLOCKED: no MRTS definition YAML files found: $MRTS_DEFINITIONS" >&2
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

set -- $definition_list
(
    cd "$MRTS_ROOT"
    "${PYTHON:-python3}" "$MRTS_ROOT/mrts/generate-rules.py" \
        -r "$@" \
        -e "$MRTS_RULES_OUT" \
        -t "$MRTS_FTW_OUT"
)

rule_count=$(find "$MRTS_RULES_OUT" -type f -name '*.conf' | wc -l | tr -d ' ')
ftw_count=$(find "$MRTS_FTW_OUT" -type f -name '*.yaml' | wc -l | tr -d ' ')

echo "MRTS generation complete"
echo "Corpus: $MRTS_CORPUS"
echo "Definitions: $(printf '%s\n' "$definition_list" | wc -l | tr -d ' ')"
echo "Rules: $rule_count ($MRTS_RULES_OUT)"
echo "FTW tests: $ftw_count ($MRTS_FTW_OUT)"
