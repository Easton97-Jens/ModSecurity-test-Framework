#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi

. "$CI_ROOT/lib/common.sh"
. "$CI_ROOT/lib/runtime-component-common.sh"

ci_validate_https_runtime_url_config || exit 77

sha_status=$(runtime_component_sha_status "$LIGHTTPD_SHA256")
LIGHTTPD_SOURCE_STAGE_DIR="${LIGHTTPD_SOURCE_STAGE_DIR:-${LIGHTTPD_SOURCE_DIR:-$LIGHTTPD_COMPONENT_ROOT/src/lighttpd-$LIGHTTPD_VERSION}}"
LIGHTTPD_STAGED_BIN="$LIGHTTPD_COMPONENT_ROOT/bin/lighttpd"
LIGHTTPD_BUILD_ROOT="${LIGHTTPD_BUILD_ROOT:-$LIGHTTPD_COMPONENT_ROOT/build/lighttpd-$LIGHTTPD_VERSION}"
LIGHTTPD_BUILD_LOG_ROOT="${LIGHTTPD_BUILD_LOG_ROOT:-$LIGHTTPD_LOG_ROOT/prepare-runtime}"
LIGHTTPD_BUILD_MISSING_DEPS_LOG="$LIGHTTPD_BUILD_LOG_ROOT/build-dependencies.missing"

assert_safe_runtime_path "$LIGHTTPD_COMPONENT_ROOT" LIGHTTPD_COMPONENT_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_RUNTIME_ROOT" LIGHTTPD_RUNTIME_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_CONFIG_ROOT" LIGHTTPD_CONFIG_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_LOG_ROOT" LIGHTTPD_LOG_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_RESULT_ROOT" LIGHTTPD_RESULT_ROOT || exit 77
assert_safe_runtime_path "$LIGHTTPD_BUILD_LOG_ROOT" LIGHTTPD_BUILD_LOG_ROOT || exit 77
runtime_component_require_under_cache "$LIGHTTPD_STAGED_BIN" "lighttpd staged binary" || exit 77
runtime_component_require_under_cache "$LIGHTTPD_BUILD_ROOT" "lighttpd build root" || exit 77
ci_require_absolute_path "$LIGHTTPD_BIN" LIGHTTPD_BIN || exit 77
if ci_path_is_system_path "$LIGHTTPD_BIN"; then
    ci_blocked "LIGHTTPD_BIN must not point at a global system path: $LIGHTTPD_BIN"
    exit 77
fi

print_binary_status() {
    binary=$1
    version_output=$("$binary" -v 2>&1 || true)
    version_matches=false
    case "$version_output" in
        *"$LIGHTTPD_VERSION"*) version_matches=true ;;
    esac
    printf 'lighttpd runtime binary: %s\n' "$binary"
    printf 'lighttpd_version=%s\n' "$LIGHTTPD_VERSION"
    printf 'lighttpd_source_url=%s\n' "$LIGHTTPD_SOURCE_URL"
    printf 'lighttpd_download_url=%s\n' "$LIGHTTPD_DOWNLOAD_URL"
    printf 'lighttpd_sha256_status=%s\n' "$sha_status"
    printf 'lighttpd_source_staged=%s\n' "$([ -d "$LIGHTTPD_SOURCE_STAGE_DIR" ] && printf true || printf false)"
    printf 'lighttpd_binary_version_output=%s\n' "$version_output"
    printf 'lighttpd_binary_version_matches_pin=%s\n' "$version_matches"
    if [ "$version_matches" != "true" ]; then
        printf 'WARN: lighttpd binary version output does not mention pinned version %s\n' "$LIGHTTPD_VERSION" >&2
    fi
}

blocked_extra="Lighttpd download is a source tarball, not a direct runtime binary.
Source staged: $([ -d "$LIGHTTPD_SOURCE_STAGE_DIR" ] && printf true || printf false)
Runtime binary available: false
Build supported: true
Build requires opt-in: ALLOW_RUNTIME_BUILDS=1
Expected build output:
  $LIGHTTPD_STAGED_BIN
or set LIGHTTPD_BIN to an executable local/common.sh-managed path."

if [ -f "$LIGHTTPD_BIN" ] && [ -x "$LIGHTTPD_BIN" ] && [ -d "$LIGHTTPD_SOURCE_STAGE_DIR" ]; then
    print_binary_status "$LIGHTTPD_BIN"
    exit 0
fi

if [ "${LIGHTTPD_BIN_WAS_SET:-0}" = "1" ] \
    && { [ ! -f "$LIGHTTPD_BIN" ] || [ ! -x "$LIGHTTPD_BIN" ]; }; then
    ci_blocked "explicit LIGHTTPD_BIN is not executable: $LIGHTTPD_BIN"
    exit 77
fi

if [ ! -d "$LIGHTTPD_SOURCE_STAGE_DIR" ]; then
    if ! require_runtime_download_opt_in; then
        write_prepare_blocked_message \
            lighttpd \
            "$LIGHTTPD_VERSION" \
            "$LIGHTTPD_SOURCE_URL" \
            "" \
            "$LIGHTTPD_LATEST_URL" \
            "$LIGHTTPD_DOWNLOAD_URL" \
            "$sha_status" \
            "$LIGHTTPD_SHA256_URL" \
            "$LIGHTTPD_STAGED_BIN" \
            "$blocked_extra"
        exit 77
    fi

    require_pinned_runtime_source lighttpd "$LIGHTTPD_VERSION" "$LIGHTTPD_SOURCE_URL" "$LIGHTTPD_DOWNLOAD_URL" "$LIGHTTPD_SHA256" || exit 77

    archive="$LIGHTTPD_COMPONENT_ROOT/downloads/lighttpd-$LIGHTTPD_VERSION.tar.xz"
    source_parent="$LIGHTTPD_COMPONENT_ROOT/src"
    download_runtime_artifact lighttpd "$LIGHTTPD_DOWNLOAD_URL" "$archive" >/dev/null || exit 77
    verify_runtime_artifact_sha256 lighttpd "$LIGHTTPD_SHA256" "$archive" || exit 77
    source_dir=$(extract_runtime_source_tar lighttpd "$archive" "$source_parent" "lighttpd-$LIGHTTPD_VERSION") || exit 77
else
    source_dir="$LIGHTTPD_SOURCE_STAGE_DIR"
fi

# A matching binary may have been staged from an existing installation. Keep
# provisioning the pinned source tree for external module headers, then reuse
# the staged binary without rebuilding stock lighttpd.
if [ -f "$LIGHTTPD_BIN" ] && [ -x "$LIGHTTPD_BIN" ]; then
    print_binary_status "$LIGHTTPD_BIN"
    printf 'lighttpd_source_dir=%s\n' "$source_dir"
    exit 0
fi

if [ "${ALLOW_RUNTIME_BUILDS:-0}" != "1" ]; then
    {
        printf 'BLOCKED: lighttpd source is staged, but local build requires ALLOW_RUNTIME_BUILDS=1.\n'
        printf 'Source staged: %s\n' "$source_dir"
        printf 'Expected local binary: %s\n' "$LIGHTTPD_STAGED_BIN"
        printf 'Build root: %s\n' "$LIGHTTPD_BUILD_ROOT"
        printf 'Build logs: %s\n' "$LIGHTTPD_BUILD_LOG_ROOT"
        printf 'No global installation was attempted.\n'
    } >&2
    exit 77
fi

mkdir -p "$LIGHTTPD_BUILD_LOG_ROOT"
missing_tools=
for tool in make tar grep find sed tee; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing_tools="$missing_tools $tool"
    fi
done
if [ ! -x "$source_dir/configure" ]; then
    if [ -x "$source_dir/autogen.sh" ]; then
        if ! command -v autoreconf >/dev/null 2>&1; then
            missing_tools="$missing_tools autoreconf"
        fi
    else
        ci_blocked "lighttpd source has neither executable configure nor executable autogen.sh: $source_dir"
        exit 77
    fi
fi

cc_bin="${CC:-}"
if [ -n "$cc_bin" ]; then
    if ! command -v "$cc_bin" >/dev/null 2>&1; then
        missing_tools="$missing_tools $cc_bin"
    fi
else
    for candidate in cc gcc clang; do
        if command -v "$candidate" >/dev/null 2>&1; then
            cc_bin=$candidate
            break
        fi
    done
    if [ -z "$cc_bin" ]; then
        missing_tools="$missing_tools C-compiler"
    fi
fi

if [ -n "$missing_tools" ]; then
    printf '%s\n' "$missing_tools" > "$LIGHTTPD_BUILD_MISSING_DEPS_LOG"
    ci_blocked "lighttpd build dependencies are missing:$missing_tools"
    exit 77
fi

if [ ! -x "$source_dir/configure" ]; then
    printf './autogen.sh\n' > "$LIGHTTPD_BUILD_LOG_ROOT/autogen-command.txt"
    if ! (cd "$source_dir" && ./autogen.sh > "$LIGHTTPD_BUILD_LOG_ROOT/autogen.stdout.log" 2> "$LIGHTTPD_BUILD_LOG_ROOT/autogen.stderr.log"); then
        ci_blocked "lighttpd autogen failed; see $LIGHTTPD_BUILD_LOG_ROOT/autogen.stderr.log"
        exit 77
    fi
fi

if [ ! -x "$source_dir/configure" ]; then
    ci_blocked "lighttpd autogen did not produce executable configure: $source_dir/configure"
    exit 77
fi

rm -rf "$LIGHTTPD_BUILD_ROOT"
mkdir -p "$LIGHTTPD_BUILD_ROOT" "$LIGHTTPD_COMPONENT_ROOT/bin" "$LIGHTTPD_COMPONENT_ROOT/lib"

configure_help="$LIGHTTPD_BUILD_LOG_ROOT/configure-help.txt"
configure_help_err="$LIGHTTPD_BUILD_LOG_ROOT/configure-help.stderr.log"
if ! "$source_dir/configure" --help > "$configure_help" 2> "$configure_help_err"; then
    ci_blocked "lighttpd configure --help failed; see $configure_help_err"
    exit 77
fi

configure_args="--prefix=$LIGHTTPD_COMPONENT_ROOT --bindir=$LIGHTTPD_COMPONENT_ROOT/bin --sbindir=$LIGHTTPD_COMPONENT_ROOT/bin --libdir=$LIGHTTPD_COMPONENT_ROOT/lib"
add_configure_flag() {
    flag=$1
    if grep -Fq -- "$flag" "$configure_help"; then
        configure_args="$configure_args $flag"
    fi
}

for flag in \
    --disable-static \
    --without-pcre2 \
    --without-zlib \
    --without-bzip2 \
    --without-brotli \
    --without-zstd \
    --without-openssl \
    --without-gnutls \
    --without-mbedtls \
    --without-wolfssl \
    --without-lua \
    --without-mysql \
    --without-pgsql \
    --without-dbi \
    --without-ldap \
    --without-krb5 \
    --without-nettle \
    --without-xxhash \
    --without-maxminddb \
    --without-webdav-props \
    --without-webdav-locks
do
    add_configure_flag "$flag"
done

printf '%s\n' "$source_dir/configure $configure_args" > "$LIGHTTPD_BUILD_LOG_ROOT/configure-command.txt"
# shellcheck disable=SC2086
if ! (cd "$LIGHTTPD_BUILD_ROOT" && CC="$cc_bin" "$source_dir/configure" $configure_args > "$LIGHTTPD_BUILD_LOG_ROOT/configure.stdout.log" 2> "$LIGHTTPD_BUILD_LOG_ROOT/configure.stderr.log"); then
    ci_blocked "lighttpd configure failed; see $LIGHTTPD_BUILD_LOG_ROOT/configure.stderr.log"
    exit 77
fi

jobs="${MAKE_JOBS:-${JOBS:-}}"
if [ -z "$jobs" ]; then
    if command -v nproc >/dev/null 2>&1; then
        jobs=$(nproc)
    else
        jobs=2
    fi
fi

printf 'make -j %s\n' "$jobs" > "$LIGHTTPD_BUILD_LOG_ROOT/make-command.txt"
if ! (cd "$LIGHTTPD_BUILD_ROOT" && make -j "$jobs" > "$LIGHTTPD_BUILD_LOG_ROOT/make.stdout.log" 2> "$LIGHTTPD_BUILD_LOG_ROOT/make.stderr.log"); then
    ci_blocked "lighttpd build failed; see $LIGHTTPD_BUILD_LOG_ROOT/make.stderr.log"
    exit 77
fi

printf 'make install\n' > "$LIGHTTPD_BUILD_LOG_ROOT/install-command.txt"
if ! (cd "$LIGHTTPD_BUILD_ROOT" && make install > "$LIGHTTPD_BUILD_LOG_ROOT/install.stdout.log" 2> "$LIGHTTPD_BUILD_LOG_ROOT/install.stderr.log"); then
    ci_blocked "lighttpd install failed; see $LIGHTTPD_BUILD_LOG_ROOT/install.stderr.log"
    exit 77
fi

if [ ! -f "$LIGHTTPD_STAGED_BIN" ] || [ ! -x "$LIGHTTPD_STAGED_BIN" ]; then
    built_candidate=$(find "$LIGHTTPD_BUILD_ROOT" -type f -name lighttpd -perm /111 2>/dev/null | sed -n '1p')
    if [ -n "$built_candidate" ]; then
        stage_executable_binary lighttpd "$built_candidate" "$LIGHTTPD_STAGED_BIN" >/dev/null || exit 77
    fi
fi

if [ ! -f "$LIGHTTPD_STAGED_BIN" ] || [ ! -x "$LIGHTTPD_STAGED_BIN" ]; then
    ci_blocked "lighttpd build did not produce executable binary: $LIGHTTPD_STAGED_BIN"
    exit 77
fi

print_binary_status "$LIGHTTPD_STAGED_BIN" | tee "$LIGHTTPD_BUILD_LOG_ROOT/version.txt"
printf 'lighttpd_build_root=%s\n' "$LIGHTTPD_BUILD_ROOT"
printf 'lighttpd_build_logs=%s\n' "$LIGHTTPD_BUILD_LOG_ROOT"
exit 0
