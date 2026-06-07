#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
FRAMEWORK_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT" && pwd)

MRTS_ROOT="${MRTS_ROOT:-$FRAMEWORK_ROOT/tools/MRTS}"
MRTS_DEFINITIONS="${MRTS_DEFINITIONS:-$FRAMEWORK_ROOT/tests/mrts/definitions}"
MRTS_RULES_OUT="${MRTS_RULES_OUT:-$FRAMEWORK_ROOT/tests/mrts/generated/rules}"
MRTS_FTW_OUT="${MRTS_FTW_OUT:-$FRAMEWORK_ROOT/tests/mrts/generated/ftw}"

if [ ! -d "$MRTS_ROOT" ]; then
    echo "BLOCKED: MRTS_ROOT missing: $MRTS_ROOT" >&2
    exit 77
fi

if [ ! -f "$MRTS_ROOT/mrts/generate-rules.py" ]; then
    echo "BLOCKED: MRTS generator missing: $MRTS_ROOT/mrts/generate-rules.py" >&2
    exit 77
fi

if [ ! -d "$MRTS_DEFINITIONS" ]; then
    echo "BLOCKED: MRTS definitions missing: $MRTS_DEFINITIONS" >&2
    exit 77
fi

definition_list=$(find "$MRTS_DEFINITIONS" -type f -name '*.yaml' | sort)
if [ -z "$definition_list" ]; then
    echo "BLOCKED: no MRTS definition YAML files found: $MRTS_DEFINITIONS" >&2
    exit 77
fi

mkdir -p "$MRTS_RULES_OUT" "$MRTS_FTW_OUT"
find "$MRTS_RULES_OUT" -type f -name '*.conf' -exec rm -f {} \;
find "$MRTS_FTW_OUT" -type f -name '*.yaml' -exec rm -f {} \;

set -- $definition_list
(
    cd "$MRTS_ROOT"
    python3 "$MRTS_ROOT/mrts/generate-rules.py" \
        -r "$@" \
        -e "$MRTS_RULES_OUT" \
        -t "$MRTS_FTW_OUT"
)

rule_count=$(find "$MRTS_RULES_OUT" -type f -name '*.conf' | wc -l | tr -d ' ')
ftw_count=$(find "$MRTS_FTW_OUT" -type f -name '*.yaml' | wc -l | tr -d ' ')

echo "MRTS generation complete"
echo "Definitions: $(printf '%s\n' "$definition_list" | wc -l | tr -d ' ')"
echo "Rules: $rule_count ($MRTS_RULES_OUT)"
echo "FTW tests: $ftw_count ($MRTS_FTW_OUT)"
