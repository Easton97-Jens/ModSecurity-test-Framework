#!/bin/sh
set -eu

# The canonical runner derives this list from the framework plan.  It contains
# only selected catalog entries that have a host-runner fixture.  A connector
# harness must acknowledge the list before it may use its narrow legacy smoke
# as input to the canonical No-CRS finalizer.
connector=${1:?connector is required}
selected_cases=${NO_CRS_SELECTED_CASES:-}

case "$connector" in
    envoy|traefik|lighttpd) ;;
    *) echo "FAIL: unsupported No-CRS selected-case consumer: $connector" >&2; exit 2 ;;
esac

[ -n "$selected_cases" ] || {
    echo "FAIL: $connector No-CRS baseline requires NO_CRS_SELECTED_CASES" >&2
    exit 1
}

allow_selected=0
deny_selected=0
other_selected=
seen_cases=' '
set -f
for runner_case in $selected_cases; do
    case "$runner_case" in
        full-lifecycle/*) case_leaf=${runner_case#full-lifecycle/} ;;
        *) case_leaf=$runner_case ;;
    esac
    case "$case_leaf" in
        *.yaml) ;;
        *)
            echo "FAIL: $connector No-CRS selected runner case is not a YAML fixture: $runner_case" >&2
            exit 1
            ;;
    esac
    case "$case_leaf" in
        ""|.*|*..*|*/*|*[!A-Za-z0-9_.-]*)
            echo "FAIL: $connector No-CRS selected runner case contains unsafe characters: $runner_case" >&2
            exit 1
            ;;
        *) ;;
    esac
    case "$seen_cases" in
        *" $runner_case "*)
            echo "FAIL: $connector No-CRS selected runner case is duplicated: $runner_case" >&2
            exit 1
            ;;
    esac
    seen_cases="$seen_cases$runner_case "
    case "$runner_case" in
        allow_without_marker.yaml) allow_selected=1 ;;
        deny_header_marker_403.yaml) deny_selected=1 ;;
        *) other_selected="${other_selected}${other_selected:+ }$runner_case" ;;
    esac
done
set +f

[ "$allow_selected" = 1 ] || {
    echo "FAIL: $connector No-CRS plan omits allow_without_marker.yaml" >&2
    exit 1
}
[ "$deny_selected" = 1 ] || {
    echo "FAIL: $connector No-CRS plan omits deny_header_marker_403.yaml" >&2
    exit 1
}

# Do not claim the selected set has run.  The current real-host harnesses only
# implement the two core probes below; the canonical finalizer emits explicit
# NOT_EXECUTED records for every other selected catalog case until a harness
# produces live case evidence for it.
printf '%s\n' "no_crs_selected_cases connector=$connector selected=$selected_cases core_runner_cases=allow_without_marker.yaml,deny_header_marker_403.yaml unrun_selected_runner_cases=${other_selected:-none}"
