#!/bin/sh
# This Parent helper is sourced by `test-with-crs` and the protected broker
# workflow after Framework common.sh. It replaces a cache-owned CRS source path
# with a fresh invocation-owned source root before Framework fetch-crs runs.

set -eu

: "${VERIFIED_RUN_ROOT:?VERIFIED_RUN_ROOT must be set}"
: "${CONNECTOR_COMPONENT_CACHE:?CONNECTOR_COMPONENT_CACHE must be set}"

fresh_crs_source_root="$VERIFIED_RUN_ROOT/crs-fresh-source"
fresh_crs_source_dir="$fresh_crs_source_root/coreruleset"

ci_require_absolute_path "$VERIFIED_RUN_ROOT" VERIFIED_RUN_ROOT || exit 77
ci_require_absolute_path "$CONNECTOR_COMPONENT_CACHE" CONNECTOR_COMPONENT_CACHE || exit 77
ci_require_absolute_path "$fresh_crs_source_root" CRS_FRESH_SOURCE_ROOT || exit 77
ci_require_absolute_path "$fresh_crs_source_dir" CRS_SOURCE_DIR || exit 77
assert_safe_runtime_path "$VERIFIED_RUN_ROOT" VERIFIED_RUN_ROOT || exit 77
assert_safe_runtime_path "$CONNECTOR_COMPONENT_CACHE" CONNECTOR_COMPONENT_CACHE || exit 77
assert_safe_runtime_path "$fresh_crs_source_root" CRS_FRESH_SOURCE_ROOT || exit 77
assert_runtime_path_under_root "$fresh_crs_source_root" "$VERIFIED_RUN_ROOT" CRS_FRESH_SOURCE_ROOT || exit 77
assert_runtime_path_under_root "$fresh_crs_source_dir" "$fresh_crs_source_root" CRS_SOURCE_DIR || exit 77

verified_run_root_canonical=$(ci_canonical_path "$VERIFIED_RUN_ROOT") || exit 77
if [ "$verified_run_root_canonical" != "$VERIFIED_RUN_ROOT" ]; then
    ci_blocked "fresh CRS verified run root must not resolve through a symlink: $VERIFIED_RUN_ROOT"
    exit 77
fi

case "$fresh_crs_source_root" in
    "$CONNECTOR_COMPONENT_CACHE"|"$CONNECTOR_COMPONENT_CACHE"/*)
        ci_blocked "fresh CRS source root must not be inside CONNECTOR_COMPONENT_CACHE"
        exit 77
        ;;
    *)
        :
        ;;
esac
case "$CONNECTOR_COMPONENT_CACHE" in
    "$fresh_crs_source_root"|"$fresh_crs_source_root"/*)
        ci_blocked "CONNECTOR_COMPONENT_CACHE must not be inside the fresh CRS source root"
        exit 77
        ;;
    *)
        :
        ;;
esac

if [ -e "$fresh_crs_source_root" ] || [ -L "$fresh_crs_source_root" ]; then
    ci_blocked "fresh CRS source root must not exist before fetch: $fresh_crs_source_root"
    exit 77
fi
if [ -e "$fresh_crs_source_dir" ] || [ -L "$fresh_crs_source_dir" ]; then
    ci_blocked "fresh CRS source directory must not exist before fetch: $fresh_crs_source_dir"
    exit 77
fi

SOURCE_ROOT="$fresh_crs_source_root"
CRS_SOURCE_DIR="$fresh_crs_source_dir"
export SOURCE_ROOT CRS_SOURCE_DIR
ci_info "using fresh CRS source root=$SOURCE_ROOT source=$CRS_SOURCE_DIR"
