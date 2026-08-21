#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors/haproxy" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"
. "$CI_ROOT/lib/runtime-component-common.sh"

# Validate the complete canonical tuple, including the inherited-environment
# snapshot, before the generic and HTX profiles reach the component lock or
# any download/cache sink.
ci_validate_https_runtime_url_config || exit 77

runtime_component_require_locked_profile \
    haproxy-spoe-spop \
    "HAPROXY_VERSION=$HAPROXY_VERSION" \
    "HAPROXY_SOURCE_URL=$HAPROXY_SOURCE_URL" \
    "HAPROXY_SHA256=$HAPROXY_SHA256" || {
    ci_blocked "HAProxy runtime configuration does not match the reviewed component lock"
    exit 77
}

# Keep the HTX host-runtime pin independent from the generic SPOE/SPOP
# provisioner tuple.  A caller must not be able to replace the reviewed HTX
# source provenance merely because this script also prepares the generic
# HAProxy runtime dependencies.
runtime_component_require_locked_profile \
    haproxy-htx \
    "HAPROXY_HTX_VERSION=$HAPROXY_HTX_VERSION" \
    "HAPROXY_HTX_SOURCE_URL=$HAPROXY_HTX_SOURCE_URL" \
    "HAPROXY_HTX_SHA256=$HAPROXY_HTX_SHA256" || {
    ci_blocked "HAProxy HTX runtime configuration does not match the reviewed component lock"
    exit 77
}

LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/haproxy-prepare}"
STATUS_FILE="$LOG_DIR/status.txt"
COMMANDS_FILE="$LOG_DIR/commands.txt"
ARTIFACTS_FILE="$LOG_DIR/artifacts.txt"
MAKE_JOBS="${MAKE_JOBS:-$(ci_default_jobs)}"
ARCHIVE_NAME="$HAPROXY_ARCHIVE_NAME"
ARCHIVE_PATH="$HAPROXY_DOWNLOAD_DIR/$ARCHIVE_NAME"
VERIFIED_ARCHIVE_PATH="$HAPROXY_RUNTIME_BUILD_DIR/$ARCHIVE_NAME"
SHA256_PATH="$HAPROXY_DOWNLOAD_DIR/$ARCHIVE_NAME.sha256"
PROVENANCE_FILE="$HAPROXY_SOURCE_DIR/.haproxy-source-provenance"
BINARY_PROVENANCE_FILE="$HAPROXY_RUNTIME_DIR/haproxy.provenance"
EXPECTED_HAPROXY_BIN="$HAPROXY_RUNTIME_DIR/sbin/haproxy"
blocked() {
    echo "haproxy_prepare: blocked $*"
    mkdir -p "$LOG_DIR"
    echo "blocked: $*" >> "$STATUS_FILE"
    exit 77
}

require_command() {
    tool=$1
    purpose=$2
    if ! command -v "$tool" >/dev/null 2>&1; then
        blocked "missing required command for $purpose: $tool"
    fi
}

require_c_header() {
    header=$1
    purpose=$2
    cc_bin="${CC:-cc}"
    check_src="$LOG_DIR/check-${header}.c"
    check_obj="$LOG_DIR/check-${header}.o"
    check_log="$LOG_DIR/check-${header}.log"

    mkdir -p "$LOG_DIR"
    cat >"$check_src" <<EOF
#include <$header>
int main(void) { return 0; }
EOF
    if $cc_bin ${CPPFLAGS:-} -c "$check_src" -o "$check_obj" >"$check_log" 2>&1; then
        rm -f "$check_src" "$check_obj" "$check_log"
        return 0
    fi
    blocked "missing development header for $purpose: <$header>; set CPPFLAGS/LDFLAGS for a local dependency path or install the matching system development package outside this run; see $check_log"
}

require_under_source_root() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$SOURCE_ROOT"|"$SOURCE_ROOT"/*) ;;
        *) blocked "$label must be under SOURCE_ROOT: $path" ;;
    esac
    case "$path" in
        "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
            blocked "$label must not be inside connector checkout: $path"
            ;;
        *) ;;
    esac
}

require_under_source_root_or_cache() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$SOURCE_ROOT"|"$SOURCE_ROOT"/*) ;;
        "$CONNECTOR_COMPONENT_CACHE"|"$CONNECTOR_COMPONENT_CACHE"/*) ;;
        *) blocked "$label must be under SOURCE_ROOT or CONNECTOR_COMPONENT_CACHE: $path" ;;
    esac
    case "$path" in
        "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
            blocked "$label must not be inside connector checkout: $path"
            ;;
        *) ;;
    esac
}

require_under_build_root() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) ;;
        *) blocked "$label must be under BUILD_ROOT: $path" ;;
    esac
    case "$path" in
        "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
            blocked "$label must not be inside connector checkout: $path"
            ;;
        *) ;;
    esac
}

require_under_runtime_root() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
}

safe_remove_dir() {
    target=$1
    real_target=$(ci_canonical_existing "$target" 2>/dev/null || true)
    [ -n "$real_target" ] || return 0
    case "$real_target" in
        "$BUILD_ROOT"/*)
            safe_remove_runtime_path "$target" "$BUILD_ROOT" "HAProxy REFRESH target" || exit 77
            ;;
        "$SOURCE_ROOT"/*)
            safe_remove_runtime_path "$target" "$SOURCE_ROOT" "HAProxy REFRESH target" || exit 77
            ;;
        *)
            blocked "unsafe REFRESH target: $real_target"
            ;;
    esac
}

run_logged() {
    label=$1
    cwd=$2
    shift 2
    log_file="$LOG_DIR/$label.log"
    {
        echo "[$label]"
        echo "cwd=$cwd"
        echo "command=$*"
        echo
    } >> "$COMMANDS_FILE"
    echo "haproxy_prepare: running $label"
    if (cd "$cwd" && "$@") >"$log_file" 2>&1; then
        echo "pass: $label log=$log_file" >> "$STATUS_FILE"
        return 0
    fi
    rc=$?
    echo "blocked: $label rc=$rc log=$log_file" >> "$STATUS_FILE"
    echo "haproxy_prepare: blocked command failed: $*"
    echo "haproxy_prepare: see log: $log_file"
    exit 77
}

validate_paths() {
    assert_safe_runtime_path "$SOURCE_ROOT" SOURCE_ROOT || exit 77
    require_under_runtime_root "$BUILD_ROOT" BUILD_ROOT
    require_under_source_root_or_cache "$HAPROXY_SOURCE_ROOT" HAPROXY_SOURCE_ROOT
    require_under_source_root_or_cache "$HAPROXY_DOWNLOAD_DIR" HAPROXY_DOWNLOAD_DIR
    require_under_source_root_or_cache "$HAPROXY_SOURCE_DIR" HAPROXY_SOURCE_DIR
    require_under_build_root "$HAPROXY_RUNTIME_BUILD_DIR" HAPROXY_RUNTIME_BUILD_DIR
    require_under_build_root "$VERIFIED_ARCHIVE_PATH" VERIFIED_ARCHIVE_PATH
    require_under_build_root "$HAPROXY_RUNTIME_BUILD_WORKTREE" HAPROXY_RUNTIME_BUILD_WORKTREE
    require_under_build_root "$HAPROXY_RUNTIME_DIR" HAPROXY_RUNTIME_DIR
    require_under_build_root "$HAPROXY_BIN" HAPROXY_BIN
    if [ "${HAPROXY_BIN_WAS_SET:-0}" = "1" ] && [ "$HAPROXY_BIN" != "$EXPECTED_HAPROXY_BIN" ]; then
        blocked "explicit HAPROXY_BIN must use the reviewed staged path: $EXPECTED_HAPROXY_BIN"
    fi
    require_under_build_root "$LOG_DIR" LOG_DIR
}

download_and_verify() {
    [ -n "$HAPROXY_SHA256" ] || blocked "HAPROXY_SHA256 is not defined"
    ci_require_https_url "$HAPROXY_SHA256_URL" HAPROXY_SHA256_URL || blocked "HAPROXY_SHA256_URL must use HTTPS"
    ci_require_https_url "$HAPROXY_SOURCE_URL" HAPROXY_SOURCE_URL || blocked "HAPROXY_SOURCE_URL must use HTTPS"
    mkdir -p "$HAPROXY_DOWNLOAD_DIR"
    download_runtime_artifact_under_root haproxy "$HAPROXY_SHA256_URL" "$SHA256_PATH" "$HAPROXY_DOWNLOAD_DIR" >/dev/null || \
        blocked "could not download the pinned HAProxy checksum"
    official_sha=$(awk -v file="$ARCHIVE_NAME" '$2 == file {print $1}' "$SHA256_PATH" | head -n 1)
    if [ -z "$official_sha" ]; then
        rm -f "$SHA256_PATH"
        blocked "official HAProxy sha256 file does not name $ARCHIVE_NAME"
    fi
    if [ "$official_sha" != "$HAPROXY_SHA256" ]; then
        rm -f "$SHA256_PATH"
        blocked "HAPROXY_SHA256 does not match official checksum for $ARCHIVE_NAME"
    fi
    download_runtime_artifact_under_root haproxy "$HAPROXY_SOURCE_URL" "$ARCHIVE_PATH" "$HAPROXY_DOWNLOAD_DIR" >/dev/null || \
        blocked "could not download the pinned HAProxy source archive"
    verify_runtime_artifact_sha256 haproxy "$HAPROXY_SHA256" "$ARCHIVE_PATH" || \
        blocked "downloaded HAProxy archive sha256 mismatch"
    # Freeze the verified bytes inside this run's private BUILD_ROOT before
    # any extraction.  A shared-cache writer can race the copy, but the
    # private copy is rehashed and becomes the only archive input below.
    mkdir -p "$HAPROXY_RUNTIME_BUILD_DIR"
    cp "$ARCHIVE_PATH" "$VERIFIED_ARCHIVE_PATH" || \
        blocked "could not copy verified HAProxy archive into the private build root"
    verify_runtime_artifact_sha256 haproxy "$HAPROXY_SHA256" "$VERIFIED_ARCHIVE_PATH" || \
        blocked "private HAProxy archive copy sha256 mismatch"
    {
        echo "haproxy_version=$HAPROXY_VERSION"
        echo "haproxy_source_url=$HAPROXY_SOURCE_URL"
        echo "haproxy_sha256_url=$HAPROXY_SHA256_URL"
        echo "haproxy_sha256=$HAPROXY_SHA256"
        echo "haproxy_archive=$ARCHIVE_PATH"
        echo "haproxy_archive_sha256_verified=1"
    } >> "$ARTIFACTS_FILE"
}

write_source_provenance() {
    runtime_component_write_provenance_file \
        "$PROVENANCE_FILE" \
        "$HAPROXY_SOURCE_DIR" \
        "HAProxy source provenance" <<EOF || blocked "could not atomically write HAProxy source provenance"
haproxy_version=$HAPROXY_VERSION
haproxy_source_url=$HAPROXY_SOURCE_URL
haproxy_sha256=$HAPROXY_SHA256
haproxy_archive=$ARCHIVE_PATH
EOF
}

verify_source_provenance() {
    [ -f "$PROVENANCE_FILE" ] || return 1
    grep -Fx "haproxy_version=$HAPROXY_VERSION" "$PROVENANCE_FILE" >/dev/null 2>&1 || return 1
    grep -Fx "haproxy_source_url=$HAPROXY_SOURCE_URL" "$PROVENANCE_FILE" >/dev/null 2>&1 || return 1
    grep -Fx "haproxy_sha256=$HAPROXY_SHA256" "$PROVENANCE_FILE" >/dev/null 2>&1 || return 1
    return 0
}

verify_binary_provenance() {
    [ -x "$HAPROXY_BIN" ] || return 1
    [ -f "$BINARY_PROVENANCE_FILE" ] || return 1
    grep -Fx "haproxy_version=$HAPROXY_VERSION" "$BINARY_PROVENANCE_FILE" >/dev/null 2>&1 || return 1
    grep -Fx "haproxy_source_url=$HAPROXY_SOURCE_URL" "$BINARY_PROVENANCE_FILE" >/dev/null 2>&1 || return 1
    grep -Fx "haproxy_sha256=$HAPROXY_SHA256" "$BINARY_PROVENANCE_FILE" >/dev/null 2>&1 || return 1
    expected_binary_sha=$(sed -n 's/^haproxy_binary_sha256=//p' "$BINARY_PROVENANCE_FILE")
    printf '%s\n' "$expected_binary_sha" | grep -Eq '^[0-9A-Fa-f]{64}$' || return 1
    actual_binary_sha=$(ci_trusted_sha256_file "$HAPROXY_BIN") || return 1
    [ "$actual_binary_sha" = "$expected_binary_sha" ] || return 1
    return 0
}

extract_source() {
    if [ -d "$HAPROXY_SOURCE_DIR" ] && [ "${REFRESH:-0}" != "1" ]; then
        if verify_source_provenance; then
            echo "haproxy_prepare: source provenance verified: $HAPROXY_SOURCE_DIR"
            return 0
        fi
        blocked "existing HAProxy source lacks current verified provenance: $HAPROXY_SOURCE_DIR"
    fi
    if [ "${REFRESH:-0}" = "1" ]; then
        safe_remove_dir "$HAPROXY_SOURCE_DIR"
    elif [ -e "$HAPROXY_SOURCE_DIR" ]; then
        blocked "source path exists but is not reusable: $HAPROXY_SOURCE_DIR"
    fi
    mkdir -p "$HAPROXY_SOURCE_DIR"
    run_logged haproxy-source-extract "$HAPROXY_DOWNLOAD_DIR" \
        tar -xf "$VERIFIED_ARCHIVE_PATH" -C "$HAPROXY_SOURCE_DIR" --strip-components=1
    write_source_provenance
}

verify_build_target() {
    # The shared source cache is retained for diagnostics and cache warming,
    # but it is not a build input.  Build validation must target the private
    # BUILD_ROOT extraction created from the archive whose digest was checked
    # in download_and_verify().
    makefile="$HAPROXY_RUNTIME_BUILD_WORKTREE/Makefile"
    [ -f "$makefile" ] || blocked "HAProxy source Makefile missing: $makefile"
    if ! grep -E 'linux-glibc' "$makefile" >/dev/null 2>&1; then
        blocked "HAProxy source Makefile does not support TARGET=linux-glibc"
    fi
    echo "haproxy_make_target=linux-glibc" >> "$ARTIFACTS_FILE"
    echo "pass: HAProxy Makefile supports TARGET=linux-glibc" >> "$STATUS_FILE"
}

prepare_build_worktree() {
    if [ -d "$HAPROXY_RUNTIME_BUILD_WORKTREE" ] && [ "${REFRESH:-0}" != "1" ]; then
        safe_remove_dir "$HAPROXY_RUNTIME_BUILD_WORKTREE"
    elif [ "${REFRESH:-0}" = "1" ]; then
        safe_remove_dir "$HAPROXY_RUNTIME_BUILD_WORKTREE"
    fi
    mkdir -p "$HAPROXY_RUNTIME_BUILD_WORKTREE"
    # Never copy from the reusable shared source directory into the build.
    # A cache writer could otherwise change a source file after metadata
    # validation but before the copy.  Extract the already verified archive
    # directly into a private BUILD_ROOT worktree instead.
    run_logged haproxy-source-extract-private "$HAPROXY_DOWNLOAD_DIR" \
        tar -xf "$VERIFIED_ARCHIVE_PATH" -C "$HAPROXY_RUNTIME_BUILD_WORKTREE" --strip-components=1
}

build_haproxy() {
    run_logged haproxy-build "$HAPROXY_RUNTIME_BUILD_WORKTREE" \
        make TARGET=linux-glibc -j "$MAKE_JOBS" haproxy
    [ -x "$HAPROXY_RUNTIME_BUILD_WORKTREE/haproxy" ] || blocked "HAProxy build completed without executable: $HAPROXY_RUNTIME_BUILD_WORKTREE/haproxy"
    mkdir -p "$(dirname "$HAPROXY_BIN")"
    run_logged haproxy-binary-stage "$HAPROXY_RUNTIME_BUILD_WORKTREE" \
        cp "$HAPROXY_RUNTIME_BUILD_WORKTREE/haproxy" "$HAPROXY_BIN"
    chmod 0755 "$HAPROXY_BIN"
    [ -x "$HAPROXY_BIN" ] || blocked "staged HAProxy binary is not executable: $HAPROXY_BIN"
    {
        echo "haproxy_version=$HAPROXY_VERSION"
        echo "haproxy_source_url=$HAPROXY_SOURCE_URL"
        echo "haproxy_sha256=$HAPROXY_SHA256"
        echo "haproxy_runtime_build_dir=$HAPROXY_RUNTIME_BUILD_DIR"
        echo "haproxy_runtime_build_worktree=$HAPROXY_RUNTIME_BUILD_WORKTREE"
        echo "haproxy_runtime_dir=$HAPROXY_RUNTIME_DIR"
        echo "haproxy_bin=$HAPROXY_BIN"
    } >> "$ARTIFACTS_FILE"
    binary_sha=$(ci_trusted_sha256_file "$HAPROXY_BIN") || blocked "trusted checksum failed for staged HAProxy binary"
    runtime_component_write_provenance_file \
        "$BINARY_PROVENANCE_FILE" \
        "$HAPROXY_RUNTIME_DIR" \
        "HAProxy binary provenance" <<EOF || blocked "could not atomically write HAProxy binary provenance"
haproxy_version=$HAPROXY_VERSION
haproxy_source_url=$HAPROXY_SOURCE_URL
haproxy_sha256=$HAPROXY_SHA256
haproxy_binary_sha256=$binary_sha
EOF
}

mkdir -p "$LOG_DIR"
: > "$STATUS_FILE"
: > "$COMMANDS_FILE"
: > "$ARTIFACTS_FILE"

validate_paths
if verify_binary_provenance && [ "${REFRESH:-0}" != "1" ]; then
    echo "haproxy_prepare: ready existing provenance-verified binary: $HAPROXY_BIN"
    echo "pass: existing binary $HAPROXY_BIN" >> "$STATUS_FILE"
    echo "haproxy_bin=$HAPROXY_BIN" >> "$ARTIFACTS_FILE"
    exit 0
fi

require_command curl "download HAProxy source and checksum"
require_command tar "extract HAProxy source"
require_command make "build HAProxy"
require_command cc "build HAProxy"
require_c_header crypt.h "HAProxy source build"

download_and_verify
extract_source
prepare_build_worktree
verify_build_target
build_haproxy

echo "haproxy_prepare: ready $HAPROXY_BIN"
