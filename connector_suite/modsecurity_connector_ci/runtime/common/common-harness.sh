#!/bin/sh
# Common shell helper functions for future connector harnesses.

msconnector_harness_require_absolute() {
    path=$1
    case "$path" in
        /*|\\*) return 0 ;;
        [A-Za-z]:/*|[A-Za-z]:\\*) return 0 ;;
        *) return 1 ;;
    esac
}

msconnector_harness_require_relative_artifact() {
    artifact=$1
    case "$artifact" in
        ""|/*|\\*|[A-Za-z]:/*|[A-Za-z]:\\*) return 1 ;;
        ".."|../*|..\\*|*/..|*\\..|*/../*|*/..\\*|*\\../*|*\\..\\*) return 1 ;;
        *) return 0 ;;
    esac
}

msconnector_harness_has_parent_segment() {
    candidate=$1
    case "$candidate" in
        ".."|../*|..\\*|*/..|*\\..|*/../*|*/..\\*|*\\../*|*\\..\\*) return 0 ;;
        *) return 1 ;;
    esac
}

msconnector_harness_require_under_root() {
    root=$1
    path=$2
    if msconnector_harness_has_parent_segment "$path"; then
        return 1
    fi
    case "$path" in
        "$root"/*|"$root"\\*) return 0 ;;
        *) return 1 ;;
    esac
}

msconnector_harness_status_pass() { message=$*; printf '%s\n' "PASS: $message"; return 0; }
msconnector_harness_status_skip() { message=$*; printf '%s\n' "SKIPPED: $message"; return 0; }
msconnector_harness_status_blocked() { message=$*; printf '%s\n' "BLOCKED: $message"; return 0; }
msconnector_harness_status_fail() { message=$*; printf '%s\n' "FAIL: $message"; return 1; }
