#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
FRAMEWORK_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT" && pwd)

MRTS_RULES_OUT="${MRTS_RULES_OUT:-$FRAMEWORK_ROOT/tests/mrts/generated/rules}"
MRTS_LOAD_FILE="${MRTS_LOAD_FILE:-$FRAMEWORK_ROOT/tests/mrts/generated/mrts.load}"

rule_list=$(find "$MRTS_RULES_OUT" -type f -name '*.conf' 2>/dev/null | sort || true)
if [ -z "$rule_list" ]; then
    echo "BLOCKED: no MRTS generated rule files found: $MRTS_RULES_OUT" >&2
    exit 77
fi

mkdir -p "$(dirname "$MRTS_LOAD_FILE")"
tmp_file="$MRTS_LOAD_FILE.tmp.$$"
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
