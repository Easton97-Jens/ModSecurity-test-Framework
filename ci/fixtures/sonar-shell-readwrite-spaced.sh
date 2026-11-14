#!/bin/sh
if exec 8<> "$1"; then
    printf '%s\n' probe >&8
    exec 8>&-
    if (printf '%s\n' unexpected >&8) 2>/dev/null; then
        exit 2
    fi
else
    exit 1
fi
