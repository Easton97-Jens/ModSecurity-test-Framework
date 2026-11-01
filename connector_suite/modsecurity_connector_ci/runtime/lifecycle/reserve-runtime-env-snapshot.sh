#!/bin/sh
# Reserve a unique, private destination for one runtime-environment snapshot.
# The provisioner later replaces this placeholder atomically, so consumers
# never observe a partially written export file.
set -eu

output_root=${1:?runtime report output root is required}

case "$output_root" in
    /*) ;;
    *)
        echo "FAIL: runtime report output root must be absolute: $output_root" >&2
        exit 2
        ;;
esac
case "$output_root" in
    *"/../"*|*/..|..|*"/./"*)
        echo "FAIL: runtime report output root contains traversal segments: $output_root" >&2
        exit 2
        ;;
esac

mkdir -p "$output_root"
umask 077
mktemp "$output_root/runtime-env-snapshot.XXXXXX.sh"
