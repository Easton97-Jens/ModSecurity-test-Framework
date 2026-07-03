#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors/haproxy" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"

LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/haproxy-prepare}"
STATUS_FILE="$LOG_DIR/status.txt"
COMMANDS_FILE="$LOG_DIR/commands.txt"
ARTIFACTS_FILE="$LOG_DIR/artifacts.txt"
MAKE_JOBS="${MAKE_JOBS:-$(ci_default_jobs)}"
ARCHIVE_NAME="haproxy-$HAPROXY_VERSION.tar.gz"
ARCHIVE_PATH="$HAPROXY_DOWNLOAD_DIR/$ARCHIVE_NAME"
SHA256_PATH="$HAPROXY_DOWNLOAD_DIR/$ARCHIVE_NAME.sha256"
PROVENANCE_FILE="$HAPROXY_SOURCE_DIR/.haproxy-source-provenance"
BINARY_PROVENANCE_FILE="$HAPROXY_RUNTIME_DIR/haproxy.provenance"

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
    require_under_build_root "$HAPROXY_RUNTIME_BUILD_WORKTREE" HAPROXY_RUNTIME_BUILD_WORKTREE
    require_under_build_root "$HAPROXY_RUNTIME_DIR" HAPROXY_RUNTIME_DIR
    require_under_build_root "$HAPROXY_BIN" HAPROXY_BIN
    require_under_build_root "$LOG_DIR" LOG_DIR
}

download_and_verify() {
    [ -n "$HAPROXY_SHA256" ] || blocked "HAPROXY_SHA256 is not defined"
    ci_require_https_url "$HAPROXY_SHA256_URL" HAPROXY_SHA256_URL || blocked "HAPROXY_SHA256_URL must use HTTPS"
    ci_require_https_url "$HAPROXY_SOURCE_URL" HAPROXY_SOURCE_URL || blocked "HAPROXY_SOURCE_URL must use HTTPS"
    mkdir -p "$HAPROXY_DOWNLOAD_DIR"
    run_logged haproxy-sha256-download "$HAPROXY_DOWNLOAD_DIR" \
        curl -fsSL --retry 3 --retry-delay 2 -o "$SHA256_PATH" "$HAPROXY_SHA256_URL"
    official_sha=$(awk -v file="$ARCHIVE_NAME" '$2 == file {print $1}' "$SHA256_PATH" | head -n 1)
    [ -n "$official_sha" ] || blocked "official HAProxy sha256 file does not name $ARCHIVE_NAME"
    if [ "$official_sha" != "$HAPROXY_SHA256" ]; then
        blocked "HAPROXY_SHA256 does not match official checksum for $ARCHIVE_NAME"
    fi
    run_logged haproxy-source-download "$HAPROXY_DOWNLOAD_DIR" \
        curl -L --fail --retry 3 --retry-delay 2 -o "$ARCHIVE_PATH" "$HAPROXY_SOURCE_URL"
    local_sha=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
    if [ "$local_sha" != "$HAPROXY_SHA256" ]; then
        blocked "downloaded HAProxy archive sha256 mismatch"
    fi
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
    {
        echo "haproxy_version=$HAPROXY_VERSION"
        echo "haproxy_source_url=$HAPROXY_SOURCE_URL"
        echo "haproxy_sha256=$HAPROXY_SHA256"
        echo "haproxy_archive=$ARCHIVE_PATH"
    } > "$PROVENANCE_FILE"
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
        tar -xf "$ARCHIVE_PATH" -C "$HAPROXY_SOURCE_DIR" --strip-components=1
    write_source_provenance
}

verify_build_target() {
    makefile="$HAPROXY_SOURCE_DIR/Makefile"
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
    run_logged haproxy-source-copy "$HAPROXY_SOURCE_DIR" \
        sh -c 'tar -cf - . | tar -xf - -C "$1"' sh "$HAPROXY_RUNTIME_BUILD_WORKTREE"
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
    {
        echo "haproxy_version=$HAPROXY_VERSION"
        echo "haproxy_source_url=$HAPROXY_SOURCE_URL"
        echo "haproxy_sha256=$HAPROXY_SHA256"
    } > "$BINARY_PROVENANCE_FILE"
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
require_command sha256sum "verify HAProxy source"
require_command make "build HAProxy"
require_command cc "build HAProxy"
require_c_header crypt.h "HAProxy source build"

download_and_verify
extract_source
verify_build_target
prepare_build_worktree
build_haproxy

echo "haproxy_prepare: ready $HAPROXY_BIN"
