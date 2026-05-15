#!/bin/sh
set -eu

MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-/root/conecter/ModSecurity_V3}"
MODSECURITY_NGINX_SOURCE_DIR="${MODSECURITY_NGINX_SOURCE_DIR:-/root/conecter/ModSecurity-nginx}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-test-Framework-build}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/nginx}"
REFRESH="${REFRESH:-0}"
BUILD_NGINX_FROM_SOURCE="${BUILD_NGINX_FROM_SOURCE:-1}"
NGINX_SOURCE_MODE="${NGINX_SOURCE_MODE:-github-release}"
NGINX_GITHUB_REPO="${NGINX_GITHUB_REPO:-https://github.com/nginx/nginx}"
NGINX_RELEASE_TAG="${NGINX_RELEASE_TAG:-latest}"
NGINX_SHA256="${NGINX_SHA256:-}"
NGINX_BUILD_DIR="${NGINX_BUILD_DIR:-$BUILD_ROOT/nginx-build}"
NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-$NGINX_BUILD_DIR/nginx-src}"
NGINX_PREFIX="${NGINX_PREFIX:-$BUILD_ROOT/nginx-runtime/nginx}"
NGINX_BINARY="${NGINX_BINARY:-$NGINX_PREFIX/sbin/nginx}"
NGINX_MODULE="${NGINX_MODULE:-$NGINX_PREFIX/modules/ngx_http_modsecurity_module.so}"
DOWNLOAD_DIR="${DOWNLOAD_DIR:-$NGINX_BUILD_DIR/downloads}"
V3_BUILD_DIR="$NGINX_BUILD_DIR/ModSecurity_V3"
NGINX_CONNECTOR_BUILD_DIR="$NGINX_BUILD_DIR/ModSecurity-nginx"
OUTPUT_DIR="$NGINX_BUILD_DIR/output"
MODSECURITY_STAGE="$OUTPUT_DIR/modsecurity"
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)

default_jobs() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    else
        getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
    fi
}

MAKE_JOBS="${MAKE_JOBS:-$(default_jobs)}"
STATUS_FILE="$LOG_DIR/status.txt"
COMMANDS_FILE="$LOG_DIR/commands.txt"
SOURCE_INFO_FILE="$LOG_DIR/source-info.txt"
ARTIFACTS_FILE="$LOG_DIR/artifacts.txt"
RESOLVED_NGINX_RELEASE_TAG=
NGINX_ARCHIVE_URL=
NGINX_ARCHIVE=

blocked() {
    echo "nginx_poc: blocked $*"
    mkdir -p "$LOG_DIR"
    echo "blocked: $*" >> "$STATUS_FILE"
    exit 77
}

fail() {
    echo "nginx_poc: fail $*"
    mkdir -p "$LOG_DIR"
    echo "fail: $*" >> "$STATUS_FILE"
    exit 1
}

canonical_existing() {
    target_path=$1
    if [ -e "$target_path" ]; then
        (cd "$target_path" 2>/dev/null && pwd -P)
    else
        return 1
    fi
}

require_absolute_generated_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *) blocked "$label must be an absolute generated path: $path" ;;
    esac
    case "$path" in
        "$REPO_ROOT"|"$REPO_ROOT"/*|/root/conecter/*)
            blocked "$label is inside a read-only or source checkout: $path"
            ;;
        *) ;;
    esac
}

safe_remove_dir() {
    target=$1
    real_target=$(canonical_existing "$target")
    case "$real_target" in
        /|/src|/tmp|/var|/home|/root|"$REPO_ROOT"|"$BUILD_ROOT"|/root/conecter/*)
            blocked "unsafe REFRESH target: $real_target"
            ;;
        *) ;;
    esac
    rm -rf "$target"
}

require_command() {
    tool=$1
    purpose=$2
    if ! command -v "$tool" >/dev/null 2>&1; then
        blocked "missing required command for $purpose: $tool"
    fi
}

run_logged_kind() {
    kind=$1
    label=$2
    cwd=$3
    shift 3
    log_file="$LOG_DIR/$label.log"
    {
        echo "[$label]"
        echo "cwd=$cwd"
        echo "command=$*"
        echo
    } >> "$COMMANDS_FILE"
    echo "nginx_poc: running $label"
    if (cd "$cwd" && "$@") >"$log_file" 2>&1; then
        echo "pass: $label log=$log_file" >> "$STATUS_FILE"
        return 0
    fi
    rc=$?
    echo "$kind: $label rc=$rc log=$log_file" >> "$STATUS_FILE"
    echo "nginx_poc: $kind command failed: $*"
    echo "nginx_poc: see log: $log_file"
    if [ "$kind" = "fail" ]; then
        exit 1
    fi
    exit 77
}

run_blocked() {
    run_logged_kind blocked "$@"
}

run_fail() {
    run_logged_kind fail "$@"
}

github_repo_path() {
    repo=$NGINX_GITHUB_REPO
    case "$repo" in
        https://github.com/*) repo=${repo#https://github.com/} ;;
        http://github.com/*) repo=${repo#http://github.com/} ;;
        git@github.com:*) repo=${repo#git@github.com:} ;;
        *) ;;
    esac
    repo=${repo%.git}
    repo=${repo%/}
    case "$repo" in
        */*) printf '%s\n' "$repo" ;;
        *) blocked "NGINX_GITHUB_REPO is not a GitHub owner/repo URL or path: $NGINX_GITHUB_REPO" ;;
    esac
}

resolve_nginx_release_tag() {
    repo_path=$(github_repo_path)
    if [ "$NGINX_RELEASE_TAG" != "latest" ]; then
        RESOLVED_NGINX_RELEASE_TAG="$NGINX_RELEASE_TAG"
        NGINX_ARCHIVE_URL="https://github.com/$repo_path/archive/refs/tags/$RESOLVED_NGINX_RELEASE_TAG.tar.gz"
        return 0
    fi

    require_command python3 "parse GitHub latest release response"
    latest_json="$DOWNLOAD_DIR/nginx-latest-release.json"
    api_url="https://api.github.com/repos/$repo_path/releases/latest"
    run_blocked nginx-github-latest-release "$DOWNLOAD_DIR" \
        curl -fsSL -H "Accept: application/vnd.github+json" -o "$latest_json" "$api_url"
    if ! RESOLVED_NGINX_RELEASE_TAG=$(python3 - "$latest_json" 2>"$LOG_DIR/nginx-latest-release-parse.log" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
tag = data.get("tag_name")
if not isinstance(tag, str) or not tag.strip():
    raise SystemExit("missing tag_name in GitHub latest release response")
print(tag.strip())
PY
); then
        blocked "failed to parse GitHub latest release response; see $LOG_DIR/nginx-latest-release-parse.log"
    fi
    [ -n "$RESOLVED_NGINX_RELEASE_TAG" ] || blocked "GitHub latest release response did not include tag_name"
    NGINX_ARCHIVE_URL="https://github.com/$repo_path/archive/refs/tags/$RESOLVED_NGINX_RELEASE_TAG.tar.gz"
}

download_nginx_source() {
    require_command curl "download NGINX GitHub archive"
    require_command tar "extract NGINX GitHub archive"
    require_command sha256sum "record NGINX archive checksum"
    mkdir -p "$DOWNLOAD_DIR"
    resolve_nginx_release_tag
    NGINX_ARCHIVE="$DOWNLOAD_DIR/nginx-$RESOLVED_NGINX_RELEASE_TAG.tar.gz"
    echo "nginx_poc: resolved nginx release tag=$RESOLVED_NGINX_RELEASE_TAG"
    echo "nginx_poc: nginx archive url=$NGINX_ARCHIVE_URL"
    run_blocked nginx-source-download "$DOWNLOAD_DIR" curl -L --fail --retry 3 --retry-delay 2 -o "$NGINX_ARCHIVE" "$NGINX_ARCHIVE_URL"
    local_sha=$(sha256sum "$NGINX_ARCHIVE" | awk '{print $1}')
    echo "nginx_poc: nginx archive sha256(local)=$local_sha"
    {
        echo "nginx_source_mode=$NGINX_SOURCE_MODE"
        echo "nginx_github_repo=$NGINX_GITHUB_REPO"
        echo "nginx_release_tag_requested=$NGINX_RELEASE_TAG"
        echo "nginx_release_tag_resolved=$RESOLVED_NGINX_RELEASE_TAG"
        echo "nginx_archive_url=$NGINX_ARCHIVE_URL"
        echo "nginx_archive=$NGINX_ARCHIVE"
        echo "nginx_archive_sha256_local=$local_sha"
    } >> "$ARTIFACTS_FILE"
    if [ -n "$NGINX_SHA256" ]; then
        if [ "$local_sha" != "$NGINX_SHA256" ]; then
            blocked "NGINX_SHA256 mismatch for $NGINX_ARCHIVE"
        fi
        echo "nginx_archive_sha256_verified=1" >> "$ARTIFACTS_FILE"
        echo "pass: nginx archive sha256 verified" >> "$STATUS_FILE"
    else
        echo "nginx_archive_sha256_verified=0; local hash recorded only" >> "$ARTIFACTS_FILE"
    fi
    mkdir -p "$NGINX_SOURCE_DIR"
    run_blocked nginx-source-extract "$DOWNLOAD_DIR" tar -xf "$NGINX_ARCHIVE" -C "$NGINX_SOURCE_DIR" --strip-components=1
}

write_git_info() {
    label=$1
    path=$2
    {
        echo "[$label]"
        echo "path=$path"
        if git -C "$path" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            echo "branch=$(git -C "$path" rev-parse --abbrev-ref HEAD)"
            echo "commit=$(git -C "$path" rev-parse HEAD)"
            echo "describe=$(git -C "$path" describe --tags --always --dirty 2>/dev/null || true)"
        else
            echo "git=not-a-git-checkout"
        fi
        echo
    } >> "$SOURCE_INFO_FILE"
}

stage_modsecurity() {
    header_dir="$V3_BUILD_DIR/headers"
    lib_dir="$V3_BUILD_DIR/src/.libs"
    lib_log="$LOG_DIR/stage-modsecurity-library.log"
    if [ ! -f "$header_dir/modsecurity/modsecurity.h" ]; then
        blocked "missing built v3 header: $header_dir/modsecurity/modsecurity.h"
    fi
    if [ ! -f "$lib_dir/libmodsecurity.so" ]; then
        blocked "missing built v3 library: $lib_dir/libmodsecurity.so"
    fi

    mkdir -p "$MODSECURITY_STAGE/include" "$MODSECURITY_STAGE/lib"
    run_blocked stage-modsecurity-headers "$V3_BUILD_DIR" cp -a "$header_dir/." "$MODSECURITY_STAGE/include/"
    {
        echo "[stage-modsecurity-library]"
        echo "cwd=$V3_BUILD_DIR"
        echo "command=cp -a $lib_dir/libmodsecurity.so* $MODSECURITY_STAGE/lib/"
        echo
    } >> "$COMMANDS_FILE"
    if cp -a "$lib_dir"/libmodsecurity.so* "$MODSECURITY_STAGE/lib/" >"$lib_log" 2>&1; then
        echo "pass: stage-modsecurity-library log=$lib_log" >> "$STATUS_FILE"
    else
        echo "blocked: stage-modsecurity-library log=$lib_log" >> "$STATUS_FILE"
        echo "nginx_poc: blocked unable to stage libmodsecurity; see $lib_log"
        exit 77
    fi
    {
        echo "modsecurity_stage=$MODSECURITY_STAGE"
        echo "modsecurity_header=$MODSECURITY_STAGE/include/modsecurity/modsecurity.h"
        echo "modsecurity_library=$MODSECURITY_STAGE/lib/libmodsecurity.so"
    } >> "$ARTIFACTS_FILE"
}

nginx_configure_script() {
    if [ -x "$NGINX_SOURCE_DIR/configure" ]; then
        printf '%s\n' "./configure"
        return 0
    fi
    if [ -x "$NGINX_SOURCE_DIR/auto/configure" ]; then
        printf '%s\n' "auto/configure"
        return 0
    fi
    blocked "NGINX source tree lacks executable configure or auto/configure: $NGINX_SOURCE_DIR"
}

build_nginx_from_source() {
    [ "$NGINX_SOURCE_MODE" = "github-release" ] || blocked "unsupported NGINX_SOURCE_MODE=$NGINX_SOURCE_MODE"
    [ "$BUILD_NGINX_FROM_SOURCE" = "1" ] || blocked "BUILD_NGINX_FROM_SOURCE must be 1 for this PoC unless a later explicit binary/module mode is implemented"

    download_nginx_source
    configure_script=$(nginx_configure_script)
    run_blocked nginx-configure "$NGINX_SOURCE_DIR" env \
        "MODSECURITY_INC=$MODSECURITY_STAGE/include" \
        "MODSECURITY_LIB=$MODSECURITY_STAGE/lib" \
        "$configure_script" \
        "--prefix=$NGINX_PREFIX" \
        "--sbin-path=$NGINX_BINARY" \
        "--modules-path=$NGINX_PREFIX/modules" \
        "--conf-path=$NGINX_PREFIX/conf/nginx.conf" \
        "--pid-path=$NGINX_PREFIX/logs/nginx.pid" \
        "--error-log-path=$NGINX_PREFIX/logs/error.log" \
        "--http-log-path=$NGINX_PREFIX/logs/access.log" \
        "--with-compat" \
        "--add-dynamic-module=$NGINX_CONNECTOR_BUILD_DIR"
    run_fail nginx-make "$NGINX_SOURCE_DIR" make "-j$MAKE_JOBS"
    run_fail nginx-make-install "$NGINX_SOURCE_DIR" make install

    module_candidate="$NGINX_SOURCE_DIR/objs/ngx_http_modsecurity_module.so"
    if [ ! -f "$module_candidate" ]; then
        fail "NGINX build completed without expected dynamic module: $module_candidate"
    fi
    mkdir -p "$NGINX_PREFIX/modules"
    cp -a "$module_candidate" "$NGINX_MODULE"

    if [ ! -x "$NGINX_BINARY" ]; then
        fail "NGINX install completed without executable binary: $NGINX_BINARY"
    fi
    if [ ! -f "$NGINX_MODULE" ]; then
        fail "NGINX install completed without dynamic module: $NGINX_MODULE"
    fi

    {
        echo "[nginx-build]"
        echo "nginx_binary=$NGINX_BINARY"
        "$NGINX_BINARY" -v 2>&1 || true
        echo "nginx_module=$NGINX_MODULE"
        echo "nginx_module_build_copy=$module_candidate"
        echo
    } >> "$SOURCE_INFO_FILE"
    {
        echo "nginx_binary=$NGINX_BINARY"
        echo "nginx_module=$NGINX_MODULE"
        echo "nginx_prefix=$NGINX_PREFIX"
    } >> "$ARTIFACTS_FILE"
}

echo "nginx_poc: MODSECURITY_V3_SOURCE_DIR=$MODSECURITY_V3_SOURCE_DIR"
echo "nginx_poc: MODSECURITY_NGINX_SOURCE_DIR=$MODSECURITY_NGINX_SOURCE_DIR"
echo "nginx_poc: BUILD_ROOT=$BUILD_ROOT"
echo "nginx_poc: NGINX_BUILD_DIR=$NGINX_BUILD_DIR"
echo "nginx_poc: LOG_DIR=$LOG_DIR"
echo "nginx_poc: NGINX_SOURCE_MODE=$NGINX_SOURCE_MODE"
echo "nginx_poc: NGINX_GITHUB_REPO=$NGINX_GITHUB_REPO"
echo "nginx_poc: NGINX_RELEASE_TAG=$NGINX_RELEASE_TAG"

require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$NGINX_BUILD_DIR" "NGINX_BUILD_DIR"
require_absolute_generated_path "$NGINX_SOURCE_DIR" "NGINX_SOURCE_DIR"
require_absolute_generated_path "$NGINX_PREFIX" "NGINX_PREFIX"
require_absolute_generated_path "$LOG_DIR" "LOG_DIR"
require_absolute_generated_path "$OUTPUT_DIR" "OUTPUT_DIR"
require_absolute_generated_path "$DOWNLOAD_DIR" "DOWNLOAD_DIR"

[ -d "$MODSECURITY_V3_SOURCE_DIR" ] || blocked "missing MODSECURITY_V3_SOURCE_DIR: $MODSECURITY_V3_SOURCE_DIR"
[ -d "$MODSECURITY_NGINX_SOURCE_DIR" ] || blocked "missing MODSECURITY_NGINX_SOURCE_DIR: $MODSECURITY_NGINX_SOURCE_DIR"

if [ -e "$NGINX_BUILD_DIR" ]; then
    if [ "$REFRESH" != "1" ]; then
        blocked "build directory exists: $NGINX_BUILD_DIR; set REFRESH=1 to replace it"
    fi
    safe_remove_dir "$NGINX_BUILD_DIR"
fi

if [ -e "$NGINX_PREFIX" ]; then
    if [ "$REFRESH" != "1" ]; then
        blocked "NGINX_PREFIX exists: $NGINX_PREFIX; set REFRESH=1 to replace it"
    fi
    safe_remove_dir "$NGINX_PREFIX"
fi

require_command git "copy-build libmodsecurity submodules"
require_command make "build libmodsecurity and NGINX"
require_command cc "build NGINX"

mkdir -p "$NGINX_BUILD_DIR" "$LOG_DIR" "$OUTPUT_DIR" "$DOWNLOAD_DIR"
: > "$STATUS_FILE"
: > "$COMMANDS_FILE"
: > "$SOURCE_INFO_FILE"
: > "$ARTIFACTS_FILE"

write_git_info "modsecurity-v3-source" "$MODSECURITY_V3_SOURCE_DIR"
write_git_info "modsecurity-nginx-source" "$MODSECURITY_NGINX_SOURCE_DIR"

run_blocked copy-modsecurity-v3 "$NGINX_BUILD_DIR" cp -a "$MODSECURITY_V3_SOURCE_DIR" "$V3_BUILD_DIR"
run_blocked copy-modsecurity-nginx "$NGINX_BUILD_DIR" cp -a "$MODSECURITY_NGINX_SOURCE_DIR" "$NGINX_CONNECTOR_BUILD_DIR"
write_git_info "modsecurity-v3-build-copy" "$V3_BUILD_DIR"
write_git_info "modsecurity-nginx-build-copy" "$NGINX_CONNECTOR_BUILD_DIR"

run_blocked v3-git-submodule-update "$V3_BUILD_DIR" git submodule update --init --recursive
run_blocked v3-build-sh "$V3_BUILD_DIR" ./build.sh
run_blocked v3-configure "$V3_BUILD_DIR" ./configure
run_blocked v3-make "$V3_BUILD_DIR" make "-j$MAKE_JOBS"
stage_modsecurity
build_nginx_from_source

echo "pass: nginx connector dynamic module built" >> "$STATUS_FILE"
echo "nginx_poc: pass binary=$NGINX_BINARY module=$NGINX_MODULE"
