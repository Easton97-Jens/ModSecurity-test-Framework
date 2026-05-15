#!/bin/sh
set -eu

MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-/root/conecter/ModSecurity_V3}"
MODSECURITY_APACHE_SOURCE_DIR="${MODSECURITY_APACHE_SOURCE_DIR:-/root/conecter/ModSecurity-apache}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-test-Framework-build}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/apache}"
REFRESH="${REFRESH:-0}"
APACHE_BUILD_ROOT="${APACHE_BUILD_ROOT:-$BUILD_ROOT/apache-build}"
DOWNLOAD_DIR="${DOWNLOAD_DIR:-$APACHE_BUILD_ROOT/downloads}"
V3_BUILD_DIR="$APACHE_BUILD_ROOT/ModSecurity_V3"
APACHE_CONNECTOR_BUILD_DIR="$APACHE_BUILD_ROOT/ModSecurity-apache"
OUTPUT_DIR="$APACHE_BUILD_ROOT/output"
MODSECURITY_STAGE="$OUTPUT_DIR/modsecurity"
BUILD_HTTPD_FROM_SOURCE="${BUILD_HTTPD_FROM_SOURCE:-0}"
HTTPD_VERSION="${HTTPD_VERSION:-2.4.67}"
HTTPD_SOURCE_URL="${HTTPD_SOURCE_URL:-https://downloads.apache.org/httpd/httpd-$HTTPD_VERSION.tar.bz2}"
HTTPD_SHA256_URL="${HTTPD_SHA256_URL:-$HTTPD_SOURCE_URL.sha256}"
APR_VERSION="${APR_VERSION:-1.7.6}"
APR_SOURCE_URL="${APR_SOURCE_URL:-https://downloads.apache.org/apr/apr-$APR_VERSION.tar.bz2}"
APR_SHA256_URL="${APR_SHA256_URL:-$APR_SOURCE_URL.sha256}"
APR_UTIL_VERSION="${APR_UTIL_VERSION:-1.6.3}"
APR_UTIL_SOURCE_URL="${APR_UTIL_SOURCE_URL:-https://downloads.apache.org/apr/apr-util-$APR_UTIL_VERSION.tar.bz2}"
APR_UTIL_SHA256_URL="${APR_UTIL_SHA256_URL:-$APR_UTIL_SOURCE_URL.sha256}"
HTTPD_BUILD_DIR="${HTTPD_BUILD_DIR:-$APACHE_BUILD_ROOT/httpd}"
HTTPD_SOURCE_DIR="${HTTPD_SOURCE_DIR:-$APACHE_BUILD_ROOT/httpd-src}"
HTTPD_PREFIX="${HTTPD_PREFIX:-$BUILD_ROOT/apache-runtime/httpd}"
BUILD_PCRE2_FROM_SOURCE="${BUILD_PCRE2_FROM_SOURCE:-0}"
PCRE_CONFIG_BIN="${PCRE_CONFIG:-}"
PCRE2_VERSION="${PCRE2_VERSION:-10.47}"
PCRE2_SOURCE_URL="${PCRE2_SOURCE_URL:-https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$PCRE2_VERSION/pcre2-$PCRE2_VERSION.tar.bz2}"
PCRE2_SHA256="${PCRE2_SHA256:-}"
PCRE2_SHA256_URL="${PCRE2_SHA256_URL:-}"
PCRE2_SOURCE_DIR="${PCRE2_SOURCE_DIR:-$APACHE_BUILD_ROOT/pcre2-src}"
PCRE2_PREFIX="${PCRE2_PREFIX:-$OUTPUT_DIR/pcre2}"
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
APXS_BIN="${APXS:-}"
APACHE_HTTPD_BIN="${APACHE_HTTPD:-${APACHE:-}}"
STATUS_FILE="$LOG_DIR/status.txt"
COMMANDS_FILE="$LOG_DIR/commands.txt"
SOURCE_INFO_FILE="$LOG_DIR/source-info.txt"
ARTIFACTS_FILE="$LOG_DIR/artifacts.txt"
HTTPD_SOURCE_BUILT=0
PCRE2_SOURCE_BUILT=0

blocked() {
    echo "apache_poc: blocked $*"
    mkdir -p "$LOG_DIR"
    echo "blocked: $*" >> "$STATUS_FILE"
    exit 77
}

fail() {
    echo "apache_poc: fail $*"
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
    echo "apache_poc: running $label"
    if (cd "$cwd" && "$@") >"$log_file" 2>&1; then
        echo "pass: $label log=$log_file" >> "$STATUS_FILE"
        return 0
    fi
    rc=$?
    echo "blocked: $label rc=$rc log=$log_file" >> "$STATUS_FILE"
    echo "apache_poc: blocked command failed: $*"
    echo "apache_poc: see log: $log_file"
    exit 77
}

download_file() {
    label=$1
    url=$2
    dest=$3
    require_command curl "download $label"
    mkdir -p "$DOWNLOAD_DIR"
    run_logged "$label-download" "$DOWNLOAD_DIR" curl -L --fail --retry 3 --retry-delay 2 -o "$dest" "$url"
    if command -v sha256sum >/dev/null 2>&1; then
        local_sha=$(sha256sum "$dest" | awk '{print $1}')
        echo "$label sha256(local)=$local_sha file=$dest" >> "$ARTIFACTS_FILE"
    fi
}

verify_sha256_url() {
    label=$1
    file=$2
    sha_url=$3
    [ -n "$sha_url" ] || return 0
    require_command sha256sum "verify $label checksum"
    sha_file="$DOWNLOAD_DIR/$label.sha256"
    download_file "$label-sha256" "$sha_url" "$sha_file"
    expected=$(awk '{print $1; exit}' "$sha_file")
    if [ -z "$expected" ]; then
        blocked "empty SHA256 file for $label: $sha_file"
    fi
    actual=$(sha256sum "$file" | awk '{print $1}')
    {
        echo "$label sha256(expected)=$expected"
        echo "$label sha256(actual)=$actual"
    } >> "$ARTIFACTS_FILE"
    if [ "$actual" != "$expected" ]; then
        blocked "SHA256 mismatch for $label"
    fi
    echo "pass: $label sha256 verified" >> "$STATUS_FILE"
}

verify_sha256_literal() {
    label=$1
    file=$2
    expected=$3
    [ -n "$expected" ] || return 0
    require_command sha256sum "verify $label checksum"
    actual=$(sha256sum "$file" | awk '{print $1}')
    {
        echo "$label sha256(expected)=$expected"
        echo "$label sha256(actual)=$actual"
    } >> "$ARTIFACTS_FILE"
    if [ "$actual" != "$expected" ]; then
        blocked "SHA256 mismatch for $label"
    fi
    echo "pass: $label sha256 verified" >> "$STATUS_FILE"
}

extract_tar_strip() {
    label=$1
    archive=$2
    dest=$3
    require_command tar "extract $label"
    mkdir -p "$dest"
    run_logged "$label-extract" "$DOWNLOAD_DIR" tar -xf "$archive" -C "$dest" --strip-components=1
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

build_pcre2_from_source() {
    require_absolute_generated_path "$PCRE2_SOURCE_DIR" "PCRE2_SOURCE_DIR"
    require_absolute_generated_path "$PCRE2_PREFIX" "PCRE2_PREFIX"
    require_command make "build PCRE2"
    require_command cc "build PCRE2"

    pcre2_archive="$DOWNLOAD_DIR/pcre2-$PCRE2_VERSION.tar.bz2"
    download_file pcre2 "$PCRE2_SOURCE_URL" "$pcre2_archive"
    verify_sha256_literal pcre2 "$pcre2_archive" "$PCRE2_SHA256"
    verify_sha256_url pcre2 "$pcre2_archive" "$PCRE2_SHA256_URL"
    if [ -z "$PCRE2_SHA256" ] && [ -z "$PCRE2_SHA256_URL" ]; then
        echo "pcre2 sha256(upstream)=not-configured; local hash recorded only" >> "$ARTIFACTS_FILE"
    fi

    extract_tar_strip pcre2 "$pcre2_archive" "$PCRE2_SOURCE_DIR"
    run_logged pcre2-configure "$PCRE2_SOURCE_DIR" ./configure "--prefix=$PCRE2_PREFIX"
    run_logged pcre2-make "$PCRE2_SOURCE_DIR" make "-j$MAKE_JOBS"
    run_logged pcre2-make-install "$PCRE2_SOURCE_DIR" make install

    PCRE_CONFIG_BIN="$PCRE2_PREFIX/bin/pcre2-config"
    if [ ! -x "$PCRE_CONFIG_BIN" ]; then
        blocked "PCRE2 source build completed without pcre2-config: $PCRE_CONFIG_BIN"
    fi
    PCRE2_SOURCE_BUILT=1
    {
        echo "pcre2_source_built=1"
        echo "pcre2_version=$PCRE2_VERSION"
        echo "pcre2_prefix=$PCRE2_PREFIX"
        echo "pcre_config=$PCRE_CONFIG_BIN"
    } >> "$ARTIFACTS_FILE"
}

resolve_pcre_config() {
    if [ -n "$PCRE_CONFIG_BIN" ]; then
        if [ ! -x "$PCRE_CONFIG_BIN" ]; then
            blocked "PCRE_CONFIG is not executable: $PCRE_CONFIG_BIN"
        fi
        return 0
    fi

    if [ "$BUILD_PCRE2_FROM_SOURCE" = "1" ]; then
        build_pcre2_from_source
        return 0
    fi

    PCRE_CONFIG_BIN=$(command -v pcre2-config 2>/dev/null || command -v pcre-config 2>/dev/null || true)
    if [ -z "$PCRE_CONFIG_BIN" ]; then
        blocked "missing PCRE config tool; set PCRE_CONFIG or BUILD_PCRE2_FROM_SOURCE=1"
    fi
}

build_httpd_from_source() {
    require_absolute_generated_path "$DOWNLOAD_DIR" "DOWNLOAD_DIR"
    require_absolute_generated_path "$HTTPD_BUILD_DIR" "HTTPD_BUILD_DIR"
    require_absolute_generated_path "$HTTPD_SOURCE_DIR" "HTTPD_SOURCE_DIR"
    require_absolute_generated_path "$HTTPD_PREFIX" "HTTPD_PREFIX"
    require_command make "build Apache httpd"
    require_command cc "build Apache httpd"
    require_command perl "build Apache httpd support scripts"

    if [ -e "$HTTPD_PREFIX" ]; then
        if [ "$REFRESH" != "1" ]; then
            blocked "HTTPD_PREFIX exists: $HTTPD_PREFIX; set REFRESH=1 to replace it or set APXS/APACHE_HTTPD explicitly"
        fi
        safe_remove_dir "$HTTPD_PREFIX"
    fi

    resolve_pcre_config

    httpd_archive="$DOWNLOAD_DIR/httpd-$HTTPD_VERSION.tar.bz2"
    apr_archive="$DOWNLOAD_DIR/apr-$APR_VERSION.tar.bz2"
    apr_util_archive="$DOWNLOAD_DIR/apr-util-$APR_UTIL_VERSION.tar.bz2"

    download_file httpd "$HTTPD_SOURCE_URL" "$httpd_archive"
    verify_sha256_url httpd "$httpd_archive" "$HTTPD_SHA256_URL"
    download_file apr "$APR_SOURCE_URL" "$apr_archive"
    verify_sha256_url apr "$apr_archive" "$APR_SHA256_URL"
    download_file apr-util "$APR_UTIL_SOURCE_URL" "$apr_util_archive"
    verify_sha256_url apr-util "$apr_util_archive" "$APR_UTIL_SHA256_URL"

    mkdir -p "$HTTPD_BUILD_DIR"
    extract_tar_strip httpd "$httpd_archive" "$HTTPD_SOURCE_DIR"
    extract_tar_strip apr "$apr_archive" "$HTTPD_SOURCE_DIR/srclib/apr"
    extract_tar_strip apr-util "$apr_util_archive" "$HTTPD_SOURCE_DIR/srclib/apr-util"

    run_logged httpd-configure "$HTTPD_BUILD_DIR" "$HTTPD_SOURCE_DIR/configure" \
        "--prefix=$HTTPD_PREFIX" \
        "--with-included-apr" \
        "--with-pcre=$PCRE_CONFIG_BIN" \
        "--enable-so" \
        "--enable-mods-shared=most" \
        "--enable-mpms-shared=all" \
        "--with-mpm=event"
    run_logged httpd-make "$HTTPD_BUILD_DIR" make "-j$MAKE_JOBS"
    run_logged httpd-make-install "$HTTPD_BUILD_DIR" make install

    APXS_BIN="$HTTPD_PREFIX/bin/apxs"
    APACHE_HTTPD_BIN="$HTTPD_PREFIX/bin/httpd"
    if [ ! -x "$APXS_BIN" ]; then
        blocked "httpd source build completed without executable apxs: $APXS_BIN"
    fi
    if [ ! -x "$APACHE_HTTPD_BIN" ]; then
        blocked "httpd source build completed without executable httpd: $APACHE_HTTPD_BIN"
    fi
    HTTPD_SOURCE_BUILT=1
}

resolve_apache_tools() {
    if [ -n "$APXS_BIN" ] || [ -n "$APACHE_HTTPD_BIN" ]; then
        if [ -z "$APXS_BIN" ] || [ -z "$APACHE_HTTPD_BIN" ]; then
            blocked "APXS and APACHE_HTTPD must both be set, or both be omitted with BUILD_HTTPD_FROM_SOURCE=1"
        fi
        if [ ! -x "$APXS_BIN" ]; then
            blocked "APXS is not executable: $APXS_BIN"
        fi
        if [ ! -x "$APACHE_HTTPD_BIN" ]; then
            blocked "Apache executable is not executable: $APACHE_HTTPD_BIN"
        fi
        return 0
    fi

    if [ "$BUILD_HTTPD_FROM_SOURCE" = "1" ]; then
        build_httpd_from_source
        return 0
    fi

    blocked "missing APXS/APACHE_HTTPD; set both explicitly or set BUILD_HTTPD_FROM_SOURCE=1"
}

record_apache_tools() {
    {
        echo "[apache-tools]"
        echo "httpd_source_built=$HTTPD_SOURCE_BUILT"
        echo "pcre2_source_built=$PCRE2_SOURCE_BUILT"
        echo "APXS=$APXS_BIN"
        "$APXS_BIN" -q CC 2>/dev/null || true
        "$APXS_BIN" -q LIBEXECDIR 2>/dev/null || true
        echo "APACHE_HTTPD=$APACHE_HTTPD_BIN"
        "$APACHE_HTTPD_BIN" -v 2>/dev/null || true
        if [ -n "$PCRE_CONFIG_BIN" ]; then
            echo "PCRE_CONFIG=$PCRE_CONFIG_BIN"
            "$PCRE_CONFIG_BIN" --version 2>/dev/null || true
        fi
        echo
    } >> "$SOURCE_INFO_FILE"
    {
        echo "httpd_source_built=$HTTPD_SOURCE_BUILT"
        echo "httpd_version=$HTTPD_VERSION"
        echo "httpd_prefix=$HTTPD_PREFIX"
        echo "apxs=$APXS_BIN"
        echo "apache_httpd=$APACHE_HTTPD_BIN"
    } >> "$ARTIFACTS_FILE"
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
    run_logged stage-modsecurity-headers "$V3_BUILD_DIR" cp -a "$header_dir/." "$MODSECURITY_STAGE/include/"
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
        echo "apache_poc: blocked unable to stage libmodsecurity; see $lib_log"
        exit 77
    fi
    {
        echo "modsecurity_stage=$MODSECURITY_STAGE"
        echo "modsecurity_header=$MODSECURITY_STAGE/include/modsecurity/modsecurity.h"
        echo "modsecurity_library=$MODSECURITY_STAGE/lib/libmodsecurity.so"
    } >> "$ARTIFACTS_FILE"
}

echo "apache_poc: MODSECURITY_V3_SOURCE_DIR=$MODSECURITY_V3_SOURCE_DIR"
echo "apache_poc: MODSECURITY_APACHE_SOURCE_DIR=$MODSECURITY_APACHE_SOURCE_DIR"
echo "apache_poc: BUILD_ROOT=$BUILD_ROOT"
echo "apache_poc: APACHE_BUILD_ROOT=$APACHE_BUILD_ROOT"
echo "apache_poc: LOG_DIR=$LOG_DIR"
echo "apache_poc: BUILD_HTTPD_FROM_SOURCE=$BUILD_HTTPD_FROM_SOURCE"

require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$APACHE_BUILD_ROOT" "APACHE_BUILD_ROOT"
require_absolute_generated_path "$LOG_DIR" "LOG_DIR"
require_absolute_generated_path "$OUTPUT_DIR" "OUTPUT_DIR"
require_absolute_generated_path "$DOWNLOAD_DIR" "DOWNLOAD_DIR"
require_absolute_generated_path "$HTTPD_BUILD_DIR" "HTTPD_BUILD_DIR"
require_absolute_generated_path "$HTTPD_SOURCE_DIR" "HTTPD_SOURCE_DIR"
require_absolute_generated_path "$HTTPD_PREFIX" "HTTPD_PREFIX"

[ -d "$MODSECURITY_V3_SOURCE_DIR" ] || blocked "missing MODSECURITY_V3_SOURCE_DIR: $MODSECURITY_V3_SOURCE_DIR"
[ -d "$MODSECURITY_APACHE_SOURCE_DIR" ] || blocked "missing MODSECURITY_APACHE_SOURCE_DIR: $MODSECURITY_APACHE_SOURCE_DIR"

if [ -e "$APACHE_BUILD_ROOT" ]; then
    if [ "$REFRESH" != "1" ]; then
        blocked "build directory exists: $APACHE_BUILD_ROOT; set REFRESH=1 to replace it"
    fi
    safe_remove_dir "$APACHE_BUILD_ROOT"
fi

mkdir -p "$APACHE_BUILD_ROOT" "$LOG_DIR" "$OUTPUT_DIR"
: > "$STATUS_FILE"
: > "$COMMANDS_FILE"
: > "$SOURCE_INFO_FILE"
: > "$ARTIFACTS_FILE"

write_git_info "modsecurity-v3-source" "$MODSECURITY_V3_SOURCE_DIR"
write_git_info "modsecurity-apache-source" "$MODSECURITY_APACHE_SOURCE_DIR"

run_logged copy-modsecurity-v3 "$APACHE_BUILD_ROOT" cp -a "$MODSECURITY_V3_SOURCE_DIR" "$V3_BUILD_DIR"
run_logged copy-modsecurity-apache "$APACHE_BUILD_ROOT" cp -a "$MODSECURITY_APACHE_SOURCE_DIR" "$APACHE_CONNECTOR_BUILD_DIR"
write_git_info "modsecurity-v3-build-copy" "$V3_BUILD_DIR"
write_git_info "modsecurity-apache-build-copy" "$APACHE_CONNECTOR_BUILD_DIR"

resolve_apache_tools
record_apache_tools

run_logged v3-git-submodule-update "$V3_BUILD_DIR" git submodule update --init --recursive
run_logged v3-build-sh "$V3_BUILD_DIR" ./build.sh
run_logged v3-configure "$V3_BUILD_DIR" ./configure
run_logged v3-make "$V3_BUILD_DIR" make "-j$MAKE_JOBS"
stage_modsecurity

run_logged apache-autogen "$APACHE_CONNECTOR_BUILD_DIR" ./autogen.sh
run_logged apache-configure "$APACHE_CONNECTOR_BUILD_DIR" ./configure "--with-libmodsecurity=$MODSECURITY_STAGE" "--with-apxs=$APXS_BIN" "--with-apache=$APACHE_HTTPD_BIN"
run_logged apache-make "$APACHE_CONNECTOR_BUILD_DIR" make

module_candidate="$APACHE_CONNECTOR_BUILD_DIR/src/.libs/mod_security3.so"
if [ ! -f "$module_candidate" ]; then
    fail "Apache connector build completed without expected module: $module_candidate"
fi

mkdir -p "$OUTPUT_DIR/apache"
cp -a "$module_candidate" "$OUTPUT_DIR/apache/mod_security3.so"
{
    echo "apache_module=$OUTPUT_DIR/apache/mod_security3.so"
    echo "apache_module_build_copy=$module_candidate"
} >> "$ARTIFACTS_FILE"

echo "pass: apache connector module built" >> "$STATUS_FILE"
echo "apache_poc: pass module=$OUTPUT_DIR/apache/mod_security3.so"
