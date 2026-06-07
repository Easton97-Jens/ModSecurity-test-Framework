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
    echo "BLOCKED: MRTS_ROOT missing: $MRTS_ROOT"
    exit 77
fi

if [ ! -f "$MRTS_ROOT/mrts/generate-rules.py" ]; then
    echo "BLOCKED: MRTS generator missing: $MRTS_ROOT/mrts/generate-rules.py"
    exit 77
fi

if [ ! -d "$MRTS_DEFINITIONS" ]; then
    echo "BLOCKED: MRTS definitions missing: $MRTS_DEFINITIONS"
    exit 77
fi

set -- "$MRTS_DEFINITIONS"/*.yaml
if [ ! -f "$1" ]; then
    echo "BLOCKED: no MRTS definition YAML files found: $MRTS_DEFINITIONS"
    exit 77
fi

mkdir -p "$MRTS_RULES_OUT" "$MRTS_FTW_OUT"
find "$MRTS_RULES_OUT" -type f -name '*.conf' -exec rm -f {} \;
find "$MRTS_FTW_OUT" -type f -name '*.yaml' -exec rm -f {} \;

python3 "$MRTS_ROOT/mrts/generate-rules.py" \
    -r "$MRTS_DEFINITIONS"/*.yaml \
    -e "$MRTS_RULES_OUT" \
    -t "$MRTS_FTW_OUT"

echo "MRTS generation complete"
echo "Rules: $MRTS_RULES_OUT"
echo "FTW tests: $MRTS_FTW_OUT"
