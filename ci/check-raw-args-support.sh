#!/bin/sh
set -eu

MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-/root/conecter/ModSecurity_V3}"

case "$MODSECURITY_V3_SOURCE_DIR" in
    /*) ;;
    *)
        echo "raw_args_support: blocked MODSECURITY_V3_SOURCE_DIR must be absolute: $MODSECURITY_V3_SOURCE_DIR"
        exit 77
        ;;
esac

if [ ! -d "$MODSECURITY_V3_SOURCE_DIR" ]; then
    echo "raw_args_support: blocked missing source: $MODSECURITY_V3_SOURCE_DIR"
    exit 77
fi

missing=""
for variable in \
    ARGS_RAW \
    ARGS_GET_RAW \
    ARGS_POST_RAW \
    ARGS_NAMES_RAW \
    ARGS_GET_NAMES_RAW \
    ARGS_POST_NAMES_RAW
do
    if ! grep -R -q "$variable" "$MODSECURITY_V3_SOURCE_DIR/headers" "$MODSECURITY_V3_SOURCE_DIR/src" "$MODSECURITY_V3_SOURCE_DIR/test" 2>/dev/null; then
        missing="$missing $variable"
    fi
done

if [ -n "$missing" ]; then
    echo "raw_args_support: unsupported-local-source missing:$missing"
    exit 0
fi

echo "raw_args_support: supported-source all RAW argument collections found"
