#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
FRAMEWORK_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT" && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$FRAMEWORK_ROOT}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
MRTS_BUILD_ROOT="${MRTS_BUILD_ROOT:-$BUILD_ROOT/mrts}"
MRTS_RULES_OUT="${MRTS_RULES_OUT:-$MRTS_BUILD_ROOT/upstream-config-tests/rules}"
MRTS_LOAD_FILE="${MRTS_LOAD_FILE:-$MRTS_BUILD_ROOT/upstream-config-tests/mrts.load}"

assert_safe_runtime_path "$MRTS_BUILD_ROOT" MRTS_BUILD_ROOT || exit 77
assert_runtime_path_under_root "$MRTS_BUILD_ROOT" "$BUILD_ROOT/mrts" MRTS_BUILD_ROOT || exit 77
assert_safe_runtime_path "$MRTS_RULES_OUT" MRTS_RULES_OUT || exit 77
assert_runtime_path_under_root "$MRTS_RULES_OUT" "$MRTS_BUILD_ROOT" MRTS_RULES_OUT || exit 77
assert_safe_runtime_path "$(dirname "$MRTS_LOAD_FILE")" MRTS_LOAD_FILE_DIR || exit 77
assert_runtime_path_under_root "$MRTS_LOAD_FILE" "$MRTS_BUILD_ROOT" MRTS_LOAD_FILE || exit 77
assert_not_system_path_for_write "$MRTS_LOAD_FILE" MRTS_LOAD_FILE || exit 77

case "$(CDPATH= cd "$MRTS_RULES_OUT" 2>/dev/null && pwd || printf '%s' "$MRTS_RULES_OUT")" in
    "$FRAMEWORK_ROOT"/tools/MRTS/generated|"$FRAMEWORK_ROOT"/tools/MRTS/generated/*|"$FRAMEWORK_ROOT"/tools/MRTS/feature_demo/generated|"$FRAMEWORK_ROOT"/tools/MRTS/feature_demo/generated/*)
        echo "BLOCKED: refusing to write MRTS load file from golden references: $MRTS_RULES_OUT" >&2
        exit 77
        ;;
    *) : ;;
esac

rule_list=$(find "$MRTS_RULES_OUT" -type f -name '*.conf' 2>/dev/null | sort || true)
if [ -z "$rule_list" ]; then
    echo "BLOCKED: no MRTS generated rule files found: $MRTS_RULES_OUT" >&2
    exit 77
fi

mkdir -p "$(dirname "$MRTS_LOAD_FILE")"
tmp_file="$MRTS_LOAD_FILE.tmp.$$"
assert_not_system_path_for_write "$tmp_file" MRTS_LOAD_FILE_TMP || exit 77
: > "$tmp_file"

printf '%s\n' "$rule_list" | while IFS= read -r rule_file; do
    rule_dir=$(CDPATH= cd "$(dirname "$rule_file")" && pwd)
    rule_base=$(basename "$rule_file")
    printf 'Include "%s/%s"\n' "$rule_dir" "$rule_base" >> "$tmp_file"
done

if [ ! -s "$tmp_file" ]; then
    rm -f "$tmp_file"
    echo "BLOCKED: refusing to write empty MRTS load file: $MRTS_LOAD_FILE" >&2
    exit 77
fi

mv "$tmp_file" "$MRTS_LOAD_FILE"
echo "MRTS load file written: $MRTS_LOAD_FILE ($(printf '%s\n' "$rule_list" | wc -l | tr -d ' ') includes)" >&2
load_dir=$(CDPATH= cd "$(dirname "$MRTS_LOAD_FILE")" && pwd)
printf '%s/%s\n' "$load_dir" "$(basename "$MRTS_LOAD_FILE")"
