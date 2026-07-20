#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

if [ "$CI_SOURCE_ROOT_WAS_SET" = "0" ]; then
    SOURCE_ROOT="${RUNNER_TEMP:-$BUILD_ROOT}/sources"
    DEFAULT_MODSECURITY_V3_SOURCE_DIR="$SOURCE_ROOT/ModSecurity_V3"
fi

AUTO_FETCH_SMOKE_SOURCES="${AUTO_FETCH_SMOKE_SOURCES:-1}"
MODSECURITY_NGINX_SOURCE_DIR="${MODSECURITY_NGINX_SOURCE_DIR:-}"
MODSECURITY_V3_SOURCE_DIR="${MODSECURITY_V3_SOURCE_DIR:-$DEFAULT_MODSECURITY_V3_SOURCE_DIR}"
REFRESH="${REFRESH:-0}"
PYTHON_BIN="${PYTHON_BIN:-$(ci_python)}"
BUILD_NGINX_FROM_SOURCE="${BUILD_NGINX_FROM_SOURCE:-1}"

# Keep the historical H1 locations exactly as they were.  Other profiles get
# isolated defaults so a binary/module built without H3 can never be reused as
# a QUIC host by accident.  Explicit caller paths (the managed cache supplies
# these) always win.
if [ -n "${NGINX_BUILD_DIR+x}" ]; then NGINX_BUILD_DIR_WAS_SET=1; else NGINX_BUILD_DIR_WAS_SET=0; fi
if [ -n "${NGINX_PREFIX+x}" ]; then NGINX_PREFIX_WAS_SET=1; else NGINX_PREFIX_WAS_SET=0; fi
if [ -n "${LOG_DIR+x}" ]; then NGINX_LOG_DIR_WAS_SET=1; else NGINX_LOG_DIR_WAS_SET=0; fi
case "$NGINX_PROTOCOL_PROFILE" in
    h1)
        NGINX_PROFILE_PATH_SUFFIX=""
        ;;
    h1-h2|h1-h2-h3-quic)
        NGINX_PROFILE_PATH_SUFFIX="-$NGINX_PROTOCOL_PROFILE"
        ;;
    *)
        # Defer the user-facing failure until the regular status/log helpers
        # below are available.
        NGINX_PROFILE_PATH_SUFFIX="-$NGINX_PROTOCOL_PROFILE"
        ;;
esac
if [ "$NGINX_BUILD_DIR_WAS_SET" = "1" ]; then
    NGINX_BUILD_DIR="$NGINX_BUILD_DIR"
else
    NGINX_BUILD_DIR="$BUILD_ROOT/nginx-build$NGINX_PROFILE_PATH_SUFFIX"
fi
if [ "$NGINX_PREFIX_WAS_SET" = "1" ]; then
    NGINX_PREFIX="$NGINX_PREFIX"
else
    NGINX_PREFIX="$BUILD_ROOT/nginx-runtime/nginx$NGINX_PROFILE_PATH_SUFFIX"
fi
if [ "$NGINX_LOG_DIR_WAS_SET" = "1" ]; then
    LOG_DIR="$LOG_DIR"
else
    LOG_DIR="$BUILD_ROOT/logs/nginx$NGINX_PROFILE_PATH_SUFFIX"
fi
NGINX_SOURCE_DIR="${NGINX_SOURCE_DIR:-$NGINX_BUILD_DIR/nginx-src}"
NGINX_BINARY="${NGINX_BINARY:-$NGINX_PREFIX/sbin/nginx}"
NGINX_MODULE="${NGINX_MODULE:-$NGINX_PREFIX/modules/ngx_http_modsecurity_module.so}"
DOWNLOAD_DIR="${NGINX_DOWNLOAD_DIR:-${DOWNLOAD_DIR:-$NGINX_BUILD_DIR/downloads}}"
NGINX_QUIC_TLS_SOURCE_DIR="${NGINX_QUIC_TLS_SOURCE_DIR:-$NGINX_BUILD_DIR/quic-tls-$NGINX_QUIC_TLS_LIBRARY-$NGINX_QUIC_TLS_VERSION}"
V3_BUILD_DIR="$NGINX_BUILD_DIR/ModSecurity_V3"
NGINX_CONNECTOR_LEGACY_BUILD_DIR="$NGINX_BUILD_DIR/ModSecurity-nginx"
OUTPUT_DIR="$NGINX_BUILD_DIR/output"
MODSECURITY_STAGE="$OUTPUT_DIR/modsecurity"
MODSECURITY_SHARED_PREFIX="${MODSECURITY_SHARED_PREFIX:-}"
if [ -n "$MODSECURITY_SHARED_PREFIX" ]; then
    MODSECURITY_STAGE="$MODSECURITY_SHARED_PREFIX"
fi
DEFAULT_NGINX_SOURCE_DIR="$CONNECTOR_ROOT/connectors/nginx"
MODSECURITY_NGINX_SOURCE_DIR="${MODSECURITY_NGINX_SOURCE_DIR:-$DEFAULT_NGINX_SOURCE_DIR}"
NGINX_ADAPTER_SOURCE_DIR="${NGINX_ADAPTER_SOURCE_DIR:-$MODSECURITY_NGINX_SOURCE_DIR}"
NGINX_MATERIALIZED_SOURCE_DIR="${NGINX_MATERIALIZED_SOURCE_DIR:-$NGINX_BUILD_DIR/connector-src}"
if [ "$MODSECURITY_NGINX_SOURCE_DIR" = "$DEFAULT_NGINX_SOURCE_DIR" ]; then
    NGINX_CONNECTOR_BUILD_DIR="$NGINX_MATERIALIZED_SOURCE_DIR"
else
    NGINX_CONNECTOR_BUILD_DIR="${NGINX_CONNECTOR_BUILD_DIR:-$NGINX_CONNECTOR_LEGACY_BUILD_DIR}"
fi
NGINX_DDEBUG_REPLACEMENT="${NGINX_DDEBUG_REPLACEMENT:-$CONNECTOR_ROOT/connectors/nginx/src/ddebug.h}"

MAKE_JOBS="${MAKE_JOBS:-$(ci_default_jobs)}"
STATUS_FILE="$LOG_DIR/status.txt"
COMMANDS_FILE="$LOG_DIR/commands.txt"
SOURCE_INFO_FILE="$LOG_DIR/source-info.txt"
ARTIFACTS_FILE="$LOG_DIR/artifacts.txt"
RESOLVED_NGINX_RELEASE_TAG=
RESOLVED_NGINX_RELEASE_ASSET_NAME=
NGINX_ARCHIVE_URL=
NGINX_ARCHIVE=
NGINX_VERIFIED_ARCHIVE=
NGINX_ARCHIVE_SHA256_LOCAL=
NGINX_SHA256_CANONICAL=
NGINX_QUIC_TLS_ARCHIVE_SHA256_LOCAL=
NGINX_PROTOCOL_BUILD_CACHE_KEY=

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

require_absolute_generated_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *) ci_blocked "$label must be an absolute generated path: $path"; exit 77 ;;
    esac
    assert_safe_runtime_path "$path" "$label" || exit 77
}

safe_remove_dir() {
    target=$1
    safe_remove_runtime_path "$target" "$BUILD_ROOT" "NGINX REFRESH target" || exit 77
}

validate_nginx_protocol_profile() {
    if ! nginx_protocol_profile_valid "$NGINX_PROTOCOL_PROFILE"; then
        blocked "unsupported NGINX_PROTOCOL_PROFILE=$NGINX_PROTOCOL_PROFILE; expected h1, h1-h2, or h1-h2-h3-quic"
    fi
}

validate_pinned_sha256() {
    value=$1
    label=$2
    if [ "${#value}" -ne 64 ] || \
        ! printf '%s' "$value" | LC_ALL=C grep -Eq '^[0-9A-Fa-f]{64}$'; then
        blocked "$label must be a pinned 64-character SHA-256 value"
    fi
}

nginx_release_asset_name_for_tag() {
    release_tag=$1
    case "$release_tag" in
        release-*) release_version=${release_tag#release-} ;;
        *) release_version=$release_tag ;;
    esac
    printf 'nginx-%s.tar.gz\n' "$release_version"
}

validate_nginx_release_asset_name() {
    asset_name=$1
    case "$asset_name" in
        *..*) blocked "NGINX_RELEASE_ASSET_NAME must not contain traversal segments" ;;
        *) : ;;
    esac
    if ! printf '%s' "$asset_name" | LC_ALL=C grep -Eq '^nginx-[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$'; then
        blocked "NGINX_RELEASE_ASSET_NAME must be a safe nginx release archive name"
    fi
}

validate_nginx_archive_configuration() {
    if [ "$NGINX_SHA256_WAS_SET" = "1" ] && [ -z "$NGINX_SHA256_REQUESTED" ]; then
        blocked "NGINX_SHA256 must not be explicitly empty"
    fi
    validate_pinned_sha256 "$NGINX_SHA256" NGINX_SHA256
    NGINX_SHA256_CANONICAL=$(printf '%s' "$NGINX_SHA256" | tr '[:upper:]' '[:lower:]')
    ci_require_safe_ref "$NGINX_RELEASE_TAG" NGINX_RELEASE_TAG || \
        blocked "NGINX_RELEASE_TAG must be a safe release reference"
    ci_require_safe_ref "$NGINX_SOURCE_GIT_REF" NGINX_SOURCE_GIT_REF || \
        blocked "NGINX_SOURCE_GIT_REF must be a safe source reference"
    if [ "$NGINX_RELEASE_TAG" != "latest" ]; then
        if [ "$NGINX_SOURCE_GIT_REF" != "$NGINX_RELEASE_TAG" ]; then
            blocked "NGINX_SOURCE_GIT_REF must equal NGINX_RELEASE_TAG for a fixed release asset"
        fi
        validate_nginx_release_asset_name "$NGINX_RELEASE_ASSET_NAME"
        expected_asset_name=$(nginx_release_asset_name_for_tag "$NGINX_RELEASE_TAG")
        if [ "$NGINX_RELEASE_ASSET_NAME" != "$expected_asset_name" ]; then
            blocked "NGINX_RELEASE_ASSET_NAME must bind NGINX_RELEASE_TAG to $expected_asset_name"
        fi
    fi
}

verify_nginx_archive_digest() {
    archive=$1
    label=$2
    [ -f "$archive" ] || blocked "$label is not a regular NGINX archive: $archive"
    NGINX_ARCHIVE_SHA256_LOCAL=$(sha256sum "$archive" | awk '{print $1}')
    validate_pinned_sha256 "$NGINX_ARCHIVE_SHA256_LOCAL" "$label local SHA-256"
    if [ "$NGINX_ARCHIVE_SHA256_LOCAL" != "$NGINX_SHA256_CANONICAL" ]; then
        blocked "NGINX_SHA256 mismatch for $archive"
    fi
}

stage_verified_nginx_archive() {
    verified_dir="$NGINX_BUILD_DIR/verified-archives"
    NGINX_VERIFIED_ARCHIVE="$verified_dir/$RESOLVED_NGINX_RELEASE_ASSET_NAME"
    verified_tmp="$verified_dir/.$RESOLVED_NGINX_RELEASE_ASSET_NAME.$$"

    mkdir -p "$verified_dir"
    run_blocked nginx-source-stage-verified "$DOWNLOAD_DIR" \
        cp "$NGINX_ARCHIVE" "$verified_tmp"
    verify_nginx_archive_digest "$verified_tmp" "staged NGINX archive"
    if ! mv "$verified_tmp" "$NGINX_VERIFIED_ARCHIVE"; then
        blocked "could not finalize verified NGINX archive: $NGINX_VERIFIED_ARCHIVE"
    fi
    verify_nginx_archive_digest "$NGINX_VERIFIED_ARCHIVE" "verified NGINX extraction archive"
}

nginx_connector_patchset_sha256() {
    "$PYTHON_BIN" - "$NGINX_ADAPTER_SOURCE_DIR" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = hashlib.sha256()
if not root.is_dir():
    print("missing")
    raise SystemExit(0)
for item in sorted(path for path in root.rglob("*") if path.is_file() and ".git" not in path.parts):
    relative = item.relative_to(root).as_posix()
    digest.update(relative.encode("utf-8", "surrogateescape"))
    digest.update(b"\0")
    digest.update(hashlib.sha256(item.read_bytes()).digest())
    digest.update(b"\0")
print(digest.hexdigest())
PY
}

nginx_common_commit() {
    git -C "$CONNECTOR_ROOT/common" rev-parse HEAD 2>/dev/null || printf '%s\n' unavailable
}

ensure_quic_tls_source() {
    nginx_protocol_profile_has_http3 "$NGINX_PROTOCOL_PROFILE" || return 0

    [ "$NGINX_QUIC_TLS_LIBRARY" = "openssl" ] || \
        blocked "H3 profile requires the pinned OpenSSL QUIC/TLS source; unsupported NGINX_QUIC_TLS_LIBRARY=$NGINX_QUIC_TLS_LIBRARY"
    [ -n "$NGINX_QUIC_TLS_VERSION" ] || blocked "H3 profile requires NGINX_QUIC_TLS_VERSION"
    [ -n "$NGINX_QUIC_TLS_SOURCE_URL" ] || blocked "H3 profile requires NGINX_QUIC_TLS_SOURCE_URL"
    validate_pinned_sha256 "$NGINX_QUIC_TLS_SOURCE_SHA256" NGINX_QUIC_TLS_SOURCE_SHA256
    if ! ci_require_https_url "$NGINX_QUIC_TLS_SOURCE_URL" NGINX_QUIC_TLS_SOURCE_URL; then
        blocked "H3 profile requires an HTTPS NGINX_QUIC_TLS_SOURCE_URL"
    fi
    case "$NGINX_QUIC_TLS_SOURCE_DIR" in
        "$NGINX_BUILD_DIR"/*) ;;
        *) blocked "NGINX_QUIC_TLS_SOURCE_DIR must be below NGINX_BUILD_DIR: $NGINX_QUIC_TLS_SOURCE_DIR" ;;
    esac
    if [ -z "$NGINX_QUIC_TLS_ARCHIVE" ]; then
        quic_tls_archive_name=$(basename "${NGINX_QUIC_TLS_SOURCE_URL%%\?*}")
        [ -n "$quic_tls_archive_name" ] || blocked "could not derive archive name from NGINX_QUIC_TLS_SOURCE_URL"
        NGINX_QUIC_TLS_ARCHIVE="$DOWNLOAD_DIR/$quic_tls_archive_name"
    fi
    require_absolute_generated_path "$NGINX_QUIC_TLS_ARCHIVE" NGINX_QUIC_TLS_ARCHIVE
    require_command tar "extract pinned NGINX QUIC TLS source"
    require_command sha256sum "verify pinned NGINX QUIC TLS source"

    if [ ! -f "$NGINX_QUIC_TLS_ARCHIVE" ]; then
        require_command curl "download pinned NGINX QUIC TLS source"
        run_blocked nginx-quic-tls-source-download "$DOWNLOAD_DIR" \
            curl -L --fail --retry 3 --retry-delay 2 -o "$NGINX_QUIC_TLS_ARCHIVE" "$NGINX_QUIC_TLS_SOURCE_URL"
    fi
    NGINX_QUIC_TLS_ARCHIVE_SHA256_LOCAL=$(sha256sum "$NGINX_QUIC_TLS_ARCHIVE" | awk '{print $1}')
    if [ "$NGINX_QUIC_TLS_ARCHIVE_SHA256_LOCAL" != "$NGINX_QUIC_TLS_SOURCE_SHA256" ]; then
        blocked "NGINX_QUIC_TLS_SOURCE_SHA256 mismatch for $NGINX_QUIC_TLS_ARCHIVE; refusing an H3 fallback build"
    fi
    mkdir -p "$NGINX_QUIC_TLS_SOURCE_DIR"
    run_blocked nginx-quic-tls-source-extract "$DOWNLOAD_DIR" \
        tar -xf "$NGINX_QUIC_TLS_ARCHIVE" -C "$NGINX_QUIC_TLS_SOURCE_DIR" --strip-components=1
    [ -f "$NGINX_QUIC_TLS_SOURCE_DIR/Configure" ] || \
        blocked "pinned NGINX QUIC TLS source lacks OpenSSL Configure: $NGINX_QUIC_TLS_SOURCE_DIR"
}

write_protocol_build_provenance() {
    NGINX_PROTOCOL_PROVENANCE_FILE="$NGINX_BUILD_DIR/nginx-protocol-build-provenance.txt"
    protocol_flags=$(nginx_protocol_profile_configure_flags "$NGINX_PROTOCOL_PROFILE" | tr '\n' ' ' | sed 's/[[:space:]]*$//') || \
        blocked "could not resolve configure flags for NGINX_PROTOCOL_PROFILE=$NGINX_PROTOCOL_PROFILE"
    connector_patchset_sha256=$(nginx_connector_patchset_sha256) || blocked "could not hash NGINX connector patchset"
    common_commit=$(nginx_common_commit)
    case "$NGINX_PROTOCOL_PROFILE" in
        h1)
            tls_library=not_used
            tls_version=
            tls_source_url=
            tls_source_sha256=
            tls_source_sha256_local=
            ;;
        h1-h2)
            tls_library=system
            tls_version=$(openssl version 2>/dev/null || printf unavailable)
            tls_source_url=
            tls_source_sha256=
            tls_source_sha256_local=
            ;;
        h1-h2-h3-quic)
            tls_library=$NGINX_QUIC_TLS_LIBRARY
            tls_version=$NGINX_QUIC_TLS_VERSION
            tls_source_url=$NGINX_QUIC_TLS_SOURCE_URL
            tls_source_sha256=$NGINX_QUIC_TLS_SOURCE_SHA256
            tls_source_sha256_local=$NGINX_QUIC_TLS_ARCHIVE_SHA256_LOCAL
            ;;
        *)
            blocked "unsupported NGINX_PROTOCOL_PROFILE: $NGINX_PROTOCOL_PROFILE"
            ;;
    esac
    NGINX_PROTOCOL_BUILD_CACHE_KEY=$(
        {
            echo "nginx_protocol_profile=$NGINX_PROTOCOL_PROFILE"
            echo "nginx_release_tag=$RESOLVED_NGINX_RELEASE_TAG"
            echo "nginx_source_git_ref=$NGINX_SOURCE_GIT_REF"
            echo "nginx_commit=$NGINX_SOURCE_GIT_REF"
            echo "nginx_source_archive_sha256=$NGINX_ARCHIVE_SHA256_LOCAL"
            echo "nginx_protocol_build_flags=$protocol_flags"
            echo "tls_library=$tls_library"
            echo "tls_version=$tls_version"
            echo "tls_source_url=$tls_source_url"
            echo "tls_source_sha256=$tls_source_sha256"
            echo "modsecurity_nginx_patchset_sha256=$connector_patchset_sha256"
            echo "common_commit=$common_commit"
            echo "cc=${CC:-cc}"
            echo "cppflags=${CPPFLAGS:-}"
            echo "cflags=${CFLAGS:-}"
            echo "cxxflags=${CXXFLAGS:-}"
            echo "ldflags=${LDFLAGS:-}"
            echo "libs=${LIBS:-}"
        } | sha256sum | awk '{print $1}'
    )
    {
        echo "nginx_protocol_profile=$NGINX_PROTOCOL_PROFILE"
        echo "nginx_release_tag=$RESOLVED_NGINX_RELEASE_TAG"
        echo "nginx_source_git_ref=$NGINX_SOURCE_GIT_REF"
        echo "nginx_commit=$NGINX_SOURCE_GIT_REF"
        echo "nginx_source_archive_sha256=$NGINX_ARCHIVE_SHA256_LOCAL"
        echo "nginx_protocol_build_flags=$protocol_flags"
        echo "http2_enabled=$(nginx_protocol_profile_has_http2 "$NGINX_PROTOCOL_PROFILE" && printf true || printf false)"
        echo "http3_enabled=$(nginx_protocol_profile_has_http3 "$NGINX_PROTOCOL_PROFILE" && printf true || printf false)"
        echo "tls_library=$tls_library"
        echo "tls_version=$tls_version"
        echo "tls_source_url=$tls_source_url"
        echo "tls_source_sha256=$tls_source_sha256"
        echo "tls_source_sha256_local=$tls_source_sha256_local"
        echo "tls_source_archive=${NGINX_QUIC_TLS_ARCHIVE:-}"
        echo "tls_source_dir=${NGINX_QUIC_TLS_SOURCE_DIR:-}"
        echo "modsecurity_nginx_patchset_sha256=$connector_patchset_sha256"
        echo "common_commit=$common_commit"
        echo "cc=${CC:-cc}"
        echo "cppflags=${CPPFLAGS:-}"
        echo "cflags=${CFLAGS:-}"
        echo "cxxflags=${CXXFLAGS:-}"
        echo "ldflags=${LDFLAGS:-}"
        echo "libs=${LIBS:-}"
        echo "nginx_protocol_build_cache_key=$NGINX_PROTOCOL_BUILD_CACHE_KEY"
    } > "$NGINX_PROTOCOL_PROVENANCE_FILE"
    cat "$NGINX_PROTOCOL_PROVENANCE_FILE" >> "$ARTIFACTS_FILE"
    echo "nginx_protocol_provenance=$NGINX_PROTOCOL_PROVENANCE_FILE" >> "$ARTIFACTS_FILE"
}

verify_nginx_protocol_build() {
    NGINX_VERSION_LOG="$LOG_DIR/nginx-version.txt"
    if ! "$NGINX_BINARY" -V > "$NGINX_VERSION_LOG" 2>&1; then
        fail "NGINX host verification failed: $NGINX_BINARY -V; see $NGINX_VERSION_LOG"
    fi
    for required_flag in $(nginx_protocol_profile_configure_flags "$NGINX_PROTOCOL_PROFILE"); do
        if ! grep -F -- "$required_flag" "$NGINX_VERSION_LOG" >/dev/null 2>&1; then
            fail "NGINX -V is missing required $NGINX_PROTOCOL_PROFILE flag $required_flag; see $NGINX_VERSION_LOG"
        fi
    done
    if nginx_protocol_profile_has_http3 "$NGINX_PROTOCOL_PROFILE" && \
        ! grep -F -- "--with-openssl=$NGINX_QUIC_TLS_SOURCE_DIR" "$NGINX_VERSION_LOG" >/dev/null 2>&1; then
        fail "NGINX -V does not bind the H3 build to the pinned TLS source; see $NGINX_VERSION_LOG"
    fi
    {
        echo "[nginx-version]"
        echo "nginx_protocol_profile=$NGINX_PROTOCOL_PROFILE"
        cat "$NGINX_VERSION_LOG"
        echo
    } >> "$SOURCE_INFO_FILE"
    {
        echo "nginx_v_log=$NGINX_VERSION_LOG"
        echo "nginx_http_ssl_configure_flag=$(grep -F -- --with-http_ssl_module "$NGINX_VERSION_LOG" >/dev/null 2>&1 && printf true || printf false)"
        echo "nginx_http_v2_configure_flag=$(grep -F -- --with-http_v2_module "$NGINX_VERSION_LOG" >/dev/null 2>&1 && printf true || printf false)"
        echo "nginx_http_v3_configure_flag=$(grep -F -- --with-http_v3_module "$NGINX_VERSION_LOG" >/dev/null 2>&1 && printf true || printf false)"
    } >> "$ARTIFACTS_FILE"
}


ensure_modsecurity_v3_source() {
    if [ -d "$MODSECURITY_V3_SOURCE_DIR" ]; then
        ci_require_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR" || blocked "unapproved ModSecurity v3 source: $MODSECURITY_V3_SOURCE_DIR"
        return 0
    fi
    if [ "$AUTO_FETCH_SMOKE_SOURCES" != "1" ]; then
        blocked "missing MODSECURITY_V3_SOURCE_DIR: $MODSECURITY_V3_SOURCE_DIR"
    fi
    echo "nginx_poc: MODSECURITY_V3_SOURCE_DIR missing; attempting auto-fetch from $MODSECURITY_V3_GIT_URL ref=$MODSECURITY_V3_GIT_REF"
    set +e
    SOURCE_ROOT="$SOURCE_ROOT" \
        MODSECURITY_V3_SOURCE_DIR="$MODSECURITY_V3_SOURCE_DIR" \
        MODSECURITY_V3_GIT_URL="$MODSECURITY_V3_GIT_URL" \
        MODSECURITY_V3_GIT_REF="$MODSECURITY_V3_GIT_REF" \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/provisioning/fetch-smoke-sources.sh" v3
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] || [ ! -d "$MODSECURITY_V3_SOURCE_DIR" ]; then
        blocked "missing MODSECURITY_V3_SOURCE_DIR after auto-fetch: $MODSECURITY_V3_SOURCE_DIR"
    fi
    ci_require_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR" || blocked "unapproved ModSecurity v3 source after auto-fetch: $MODSECURITY_V3_SOURCE_DIR"
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

copy_sanitized_source() {
    label=$1
    source_dir=$2
    dest_dir=$3
    require_command tar "copy sanitized $label source"
    log_file="$LOG_DIR/$label.log"
    archive="$LOG_DIR/$label.tar"
    mkdir -p "$dest_dir"
    {
        echo "[$label]"
        echo "source=$source_dir"
        echo "dest=$dest_dir"
        echo "excludes=.git .github .travis.yml .deps __pycache__ autom4te.cache build artifacts"
        echo
    } >> "$COMMANDS_FILE"
    echo "nginx_poc: running $label"
    if (cd "$source_dir" && tar \
        --exclude='./.git' \
        --exclude='./.github' \
        --exclude='./.travis.yml' \
        --exclude='./.deps' \
        --exclude='./__pycache__' \
        --exclude='./autom4te.cache' \
        --exclude='*.o' \
        --exclude='*.lo' \
        --exclude='*.la' \
        --exclude='*.so' \
        --exclude='*.log' \
        --exclude='./objs' \
        -cf "$archive" .) >"$log_file" 2>&1 \
        && tar -xf "$archive" -C "$dest_dir" >>"$log_file" 2>&1; then
        rm -f "$archive"
        echo "pass: $label log=$log_file" >> "$STATUS_FILE"
        return 0
    fi
    rc=$?
    echo "blocked: $label rc=$rc log=$log_file" >> "$STATUS_FILE"
    echo "nginx_poc: blocked sanitized copy failed: $label"
    echo "nginx_poc: see log: $log_file"
    exit 77
}

overlay_nginx_debug_header() {
    target="$NGINX_CONNECTOR_BUILD_DIR/src/ddebug.h"
    if [ -f "$target" ]; then
        {
            echo "[nginx-debug-header-overlay]"
            echo "status=kept-source-header"
            echo "target=$target"
            echo
        } >> "$COMMANDS_FILE"
        echo "nginx_debug_header=source:$target" >> "$ARTIFACTS_FILE"
        return 0
    fi
    if [ ! -f "$NGINX_DDEBUG_REPLACEMENT" ]; then
        blocked "missing repo-owned NGINX debug header replacement: $NGINX_DDEBUG_REPLACEMENT"
    fi
    mkdir -p "$NGINX_CONNECTOR_BUILD_DIR/src"
    log_file="$LOG_DIR/nginx-debug-header-overlay.log"
    {
        echo "[nginx-debug-header-overlay]"
        echo "source=$NGINX_DDEBUG_REPLACEMENT"
        echo "target=$target"
        echo
    } >> "$COMMANDS_FILE"
    if cp "$NGINX_DDEBUG_REPLACEMENT" "$target" >"$log_file" 2>&1; then
        echo "pass: nginx-debug-header-overlay log=$log_file" >> "$STATUS_FILE"
        echo "nginx_debug_header=repo-owned:$NGINX_DDEBUG_REPLACEMENT -> $target" >> "$ARTIFACTS_FILE"
        return 0
    fi
    echo "blocked: nginx-debug-header-overlay log=$log_file" >> "$STATUS_FILE"
    echo "nginx_poc: blocked unable to overlay NGINX debug header; see $log_file"
    exit 77
}

materialize_nginx_connector_source() {
    run_blocked materialize-nginx-connector-source "$CONNECTOR_ROOT" \
        env FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$FRAMEWORK_ROOT/ci/provisioning/materialize-connector-source.sh" \
        --connector nginx \
        --adapter-dir "$NGINX_ADAPTER_SOURCE_DIR" \
        --dest-dir "$NGINX_CONNECTOR_BUILD_DIR"
    for required_file in \
        config \
        src/ddebug.h \
        src/ngx_http_modsecurity_access.c \
        src/ngx_http_modsecurity_body_filter.c \
        src/ngx_http_modsecurity_common.h \
        src/ngx_http_modsecurity_header_filter.c \
        src/ngx_http_modsecurity_log.c \
        src/ngx_http_modsecurity_module.c
    do
        if [ ! -f "$NGINX_CONNECTOR_BUILD_DIR/$required_file" ]; then
            blocked "materialized NGINX connector source is missing $required_file: $NGINX_CONNECTOR_BUILD_DIR"
        fi
    done
    {
        echo "nginx_connector_source=$NGINX_CONNECTOR_BUILD_DIR"
        echo "nginx_connector_source_manifest=$NGINX_CONNECTOR_BUILD_DIR/materialized-source.json"
        echo "nginx_connector_source_manifest_md=$NGINX_CONNECTOR_BUILD_DIR/MATERIALIZED_SOURCE.md"
        echo "nginx_debug_header=adapter-owned-materialized:$NGINX_CONNECTOR_BUILD_DIR/src/ddebug.h"
    } >> "$ARTIFACTS_FILE"
}

github_repo_path() {
    repo=$NGINX_SOURCE_REPO_URL
    ci_require_https_github_repo_url "$repo" NGINX_SOURCE_REPO_URL || blocked "NGINX_SOURCE_REPO_URL must use HTTPS GitHub owner/repo form"
    case "$repo" in
        https://github.com/*) repo=${repo#https://github.com/} ;;
        *) ;;
    esac
    repo=${repo%.git}
    repo=${repo%/}
    case "$repo" in
        */*/*) blocked "NGINX_SOURCE_REPO_URL must be a plain GitHub owner/repo URL: $NGINX_SOURCE_REPO_URL" ;;
        */*) printf '%s\n' "$repo" ;;
        *) blocked "NGINX_SOURCE_REPO_URL is not a GitHub owner/repo URL or path: $NGINX_SOURCE_REPO_URL" ;;
    esac
}

resolve_nginx_release_tag() {
    repo_path=$(github_repo_path)
    if [ "$NGINX_RELEASE_TAG" != "latest" ]; then
        RESOLVED_NGINX_RELEASE_TAG="$NGINX_RELEASE_TAG"
        ci_require_safe_ref "$RESOLVED_NGINX_RELEASE_TAG" RESOLVED_NGINX_RELEASE_TAG || \
            blocked "resolved NGINX release tag must be safe"
        RESOLVED_NGINX_RELEASE_ASSET_NAME="$NGINX_RELEASE_ASSET_NAME"
        validate_nginx_release_asset_name "$RESOLVED_NGINX_RELEASE_ASSET_NAME"
        NGINX_ARCHIVE_URL="https://github.com/$repo_path/releases/download/$RESOLVED_NGINX_RELEASE_TAG/$RESOLVED_NGINX_RELEASE_ASSET_NAME"
        return 0
    fi

    require_command "$PYTHON_BIN" "parse GitHub latest release response"
    latest_json="$DOWNLOAD_DIR/nginx-latest-release.json"
    latest_tmp="$DOWNLOAD_DIR/nginx-latest-release.json.tmp"
    api_url="https://api.github.com/repos/$repo_path/releases/latest"
    mkdir -p "$DOWNLOAD_DIR"
    {
        echo "[nginx-github-latest-release]"
        echo "cwd=$DOWNLOAD_DIR"
        echo "command=curl -fsSL --retry 3 --retry-delay 2 -H Accept: application/vnd.github+json -o $latest_tmp $api_url"
        echo
    } >> "$COMMANDS_FILE"
    if curl -fsSL --retry 3 --retry-delay 2 -H "Accept: application/vnd.github+json" -o "$latest_tmp" "$api_url" >"$LOG_DIR/nginx-github-latest-release.log" 2>&1; then
        mv "$latest_tmp" "$latest_json"
        echo "pass: nginx-github-latest-release log=$LOG_DIR/nginx-github-latest-release.log" >> "$STATUS_FILE"
    elif [ -s "$latest_json" ]; then
        rm -f "$latest_tmp"
        echo "warn: blocked_network nginx-github-latest-release; using cached $latest_json log=$LOG_DIR/nginx-github-latest-release.log" >> "$STATUS_FILE"
        echo "nginx_poc: blocked_network latest release lookup failed; using cached $latest_json"
    else
        rm -f "$latest_tmp"
        echo "blocked: nginx-github-latest-release log=$LOG_DIR/nginx-github-latest-release.log" >> "$STATUS_FILE"
        echo "nginx_poc: blocked command failed: curl latest release $api_url"
        echo "nginx_poc: see log: $LOG_DIR/nginx-github-latest-release.log"
        exit 77
    fi
    if ! RESOLVED_NGINX_RELEASE_TAG=$("$PYTHON_BIN" - "$latest_json" 2>"$LOG_DIR/nginx-latest-release-parse.log" <<'PY'
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
    ci_require_safe_ref "$RESOLVED_NGINX_RELEASE_TAG" RESOLVED_NGINX_RELEASE_TAG || \
        blocked "resolved NGINX release tag must be safe"
    RESOLVED_NGINX_RELEASE_ASSET_NAME=$(nginx_release_asset_name_for_tag "$RESOLVED_NGINX_RELEASE_TAG")
    validate_nginx_release_asset_name "$RESOLVED_NGINX_RELEASE_ASSET_NAME"
    NGINX_ARCHIVE_URL="https://github.com/$repo_path/releases/download/$RESOLVED_NGINX_RELEASE_TAG/$RESOLVED_NGINX_RELEASE_ASSET_NAME"
}

download_nginx_source() {
    # Defend the archive trust boundary again at the point of use.  This must
    # happen before a latest lookup, cache selection, or archive download.
    validate_nginx_archive_configuration
    require_command curl "download NGINX GitHub archive"
    require_command tar "extract NGINX GitHub archive"
    require_command sha256sum "verify NGINX archive checksum"
    mkdir -p "$DOWNLOAD_DIR"
    resolve_nginx_release_tag
    NGINX_ARCHIVE="$DOWNLOAD_DIR/$RESOLVED_NGINX_RELEASE_ASSET_NAME"
    echo "nginx_poc: resolved nginx release tag=$RESOLVED_NGINX_RELEASE_TAG"
    echo "nginx_poc: resolved nginx release asset=$RESOLVED_NGINX_RELEASE_ASSET_NAME"
    echo "nginx_poc: nginx archive url=$NGINX_ARCHIVE_URL"
    if [ -f "$NGINX_ARCHIVE" ] && [ "$REFRESH" != "1" ]; then
        echo "nginx_poc: reusing cached nginx archive=$NGINX_ARCHIVE"
    else
        download_tmp="$NGINX_ARCHIVE.download.$$"
        run_blocked nginx-source-download "$DOWNLOAD_DIR" \
            curl -L --fail --retry 3 --retry-delay 2 -o "$download_tmp" "$NGINX_ARCHIVE_URL"
        if ! mv "$download_tmp" "$NGINX_ARCHIVE"; then
            blocked "could not place downloaded NGINX archive: $NGINX_ARCHIVE"
        fi
    fi

    verify_nginx_archive_digest "$NGINX_ARCHIVE" "selected NGINX archive"
    stage_verified_nginx_archive
    echo "nginx_poc: nginx archive sha256(verified)=$NGINX_ARCHIVE_SHA256_LOCAL"
    {
        echo "nginx_source_mode=$NGINX_SOURCE_MODE"
        echo "nginx_source_repo_url=$NGINX_SOURCE_REPO_URL"
        echo "nginx_github_repo_compat=$NGINX_GITHUB_REPO"
        echo "nginx_release_tag_requested=$NGINX_RELEASE_TAG"
        echo "nginx_source_git_ref=$NGINX_SOURCE_GIT_REF"
        echo "nginx_release_tag_resolved=$RESOLVED_NGINX_RELEASE_TAG"
        echo "nginx_release_asset_requested=$NGINX_RELEASE_ASSET_NAME"
        echo "nginx_release_asset_resolved=$RESOLVED_NGINX_RELEASE_ASSET_NAME"
        echo "nginx_archive_url=$NGINX_ARCHIVE_URL"
        echo "nginx_archive_candidate=$NGINX_ARCHIVE"
        echo "nginx_archive=$NGINX_VERIFIED_ARCHIVE"
        echo "nginx_archive_sha256_expected=$NGINX_SHA256_CANONICAL"
        echo "nginx_archive_sha256_local=$NGINX_ARCHIVE_SHA256_LOCAL"
        echo "nginx_archive_sha256_verified=1"
    } >> "$ARTIFACTS_FILE"
    echo "pass: nginx archive sha256 verified" >> "$STATUS_FILE"
    mkdir -p "$NGINX_SOURCE_DIR"
    run_blocked nginx-source-extract "$DOWNLOAD_DIR" tar -xf "$NGINX_VERIFIED_ARCHIVE" -C "$NGINX_SOURCE_DIR" --strip-components=1
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
    if [ -n "$MODSECURITY_SHARED_PREFIX" ]; then
        if [ ! -f "$MODSECURITY_STAGE/include/modsecurity/modsecurity.h" ]; then
            blocked "missing shared v3 header: $MODSECURITY_STAGE/include/modsecurity/modsecurity.h"
        fi
        if [ ! -f "$MODSECURITY_STAGE/lib/libmodsecurity.so" ]; then
            blocked "missing shared v3 library: $MODSECURITY_STAGE/lib/libmodsecurity.so"
        fi
        {
            echo "modsecurity_stage=$MODSECURITY_STAGE"
            echo "modsecurity_header=$MODSECURITY_STAGE/include/modsecurity/modsecurity.h"
            echo "modsecurity_library=$MODSECURITY_STAGE/lib/libmodsecurity.so"
            echo "modsecurity_shared_prefix=$MODSECURITY_SHARED_PREFIX"
            echo "modsecurity_shared_build_id=${MODSECURITY_BUILD_ID:-}"
        } >> "$ARTIFACTS_FILE"
        echo "pass: shared libmodsecurity reused from $MODSECURITY_SHARED_PREFIX" >> "$STATUS_FILE"
        return 0
    fi

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
    ensure_quic_tls_source
    write_protocol_build_provenance
    configure_script=$(nginx_configure_script)
    set -- \
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
    case "$NGINX_PROTOCOL_PROFILE" in
        h1)
            ;;
        h1-h2)
            set -- "$@" --with-http_ssl_module --with-http_v2_module
            ;;
        h1-h2-h3-quic)
            set -- "$@" --with-http_ssl_module --with-http_v2_module --with-http_v3_module \
                "--with-openssl=$NGINX_QUIC_TLS_SOURCE_DIR"
            ;;
        *)
            blocked "unsupported NGINX_PROTOCOL_PROFILE=$NGINX_PROTOCOL_PROFILE"
            ;;
    esac
    run_blocked nginx-configure "$NGINX_SOURCE_DIR" env \
        "MSCONNECTOR_COMMON_INC=$CONNECTOR_ROOT/common/include" \
        "MODSECURITY_INC=$MODSECURITY_STAGE/include" \
        "MODSECURITY_LIB=$MODSECURITY_STAGE/lib" \
        "$@"
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
    verify_nginx_protocol_build

    {
        echo "[nginx-build]"
        echo "nginx_binary=$NGINX_BINARY"
        echo "nginx_protocol_profile=$NGINX_PROTOCOL_PROFILE"
        cat "$NGINX_VERSION_LOG"
        echo "nginx_module=$NGINX_MODULE"
        echo "nginx_module_build_copy=$module_candidate"
        echo
    } >> "$SOURCE_INFO_FILE"
    {
        echo "nginx_binary=$NGINX_BINARY"
        echo "nginx_module=$NGINX_MODULE"
        echo "nginx_prefix=$NGINX_PREFIX"
        echo "nginx_protocol_profile=$NGINX_PROTOCOL_PROFILE"
        echo "nginx_protocol_build_cache_key=$NGINX_PROTOCOL_BUILD_CACHE_KEY"
    } >> "$ARTIFACTS_FILE"
}

echo "nginx_poc: MODSECURITY_V3_SOURCE_DIR=$MODSECURITY_V3_SOURCE_DIR"
echo "nginx_poc: MODSECURITY_NGINX_SOURCE_DIR=$MODSECURITY_NGINX_SOURCE_DIR"
echo "nginx_poc: BUILD_ROOT=$BUILD_ROOT"
echo "nginx_poc: NGINX_BUILD_DIR=$NGINX_BUILD_DIR"
echo "nginx_poc: LOG_DIR=$LOG_DIR"
echo "nginx_poc: NGINX_SOURCE_MODE=$NGINX_SOURCE_MODE"
echo "nginx_poc: NGINX_SOURCE_REPO_URL=$NGINX_SOURCE_REPO_URL"
echo "nginx_poc: NGINX_RELEASE_TAG=$NGINX_RELEASE_TAG"
echo "nginx_poc: NGINX_SOURCE_GIT_REF=$NGINX_SOURCE_GIT_REF"
echo "nginx_poc: NGINX_PROTOCOL_PROFILE=$NGINX_PROTOCOL_PROFILE"

validate_nginx_protocol_profile
validate_nginx_archive_configuration
require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$NGINX_BUILD_DIR" "NGINX_BUILD_DIR"
require_absolute_generated_path "$NGINX_SOURCE_DIR" "NGINX_SOURCE_DIR"
require_absolute_generated_path "$NGINX_PREFIX" "NGINX_PREFIX"
require_absolute_generated_path "$NGINX_CONNECTOR_BUILD_DIR" "NGINX_CONNECTOR_BUILD_DIR"
require_absolute_generated_path "$LOG_DIR" "LOG_DIR"
require_absolute_generated_path "$OUTPUT_DIR" "OUTPUT_DIR"
if [ -n "$MODSECURITY_SHARED_PREFIX" ]; then
    require_absolute_generated_path "$MODSECURITY_SHARED_PREFIX" "MODSECURITY_SHARED_PREFIX"
fi
require_absolute_generated_path "$DOWNLOAD_DIR" "DOWNLOAD_DIR"
if nginx_protocol_profile_has_http3 "$NGINX_PROTOCOL_PROFILE"; then
    require_absolute_generated_path "$NGINX_QUIC_TLS_SOURCE_DIR" "NGINX_QUIC_TLS_SOURCE_DIR"
fi

ensure_modsecurity_v3_source
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

require_command git "verify and record ModSecurity v3 provenance"
require_command make "build libmodsecurity and NGINX"
require_command cc "build NGINX"

mkdir -p "$NGINX_BUILD_DIR" "$LOG_DIR" "$OUTPUT_DIR" "$DOWNLOAD_DIR"
: > "$STATUS_FILE"
: > "$COMMANDS_FILE"
: > "$SOURCE_INFO_FILE"
: > "$ARTIFACTS_FILE"

write_git_info "modsecurity-v3-source" "$MODSECURITY_V3_SOURCE_DIR"
write_git_info "modsecurity-nginx-source" "$MODSECURITY_NGINX_SOURCE_DIR"

if [ -z "$MODSECURITY_SHARED_PREFIX" ]; then
    run_blocked copy-modsecurity-v3 "$NGINX_BUILD_DIR" cp -a "$MODSECURITY_V3_SOURCE_DIR" "$V3_BUILD_DIR"
else
    {
        echo "[modsecurity-v3-shared-build]"
        echo "source=$MODSECURITY_V3_SOURCE_DIR"
        echo "prefix=$MODSECURITY_SHARED_PREFIX"
        echo "build_id=${MODSECURITY_BUILD_ID:-}"
        echo
    } >> "$SOURCE_INFO_FILE"
fi
if [ "$MODSECURITY_NGINX_SOURCE_DIR" = "$DEFAULT_NGINX_SOURCE_DIR" ]; then
    materialize_nginx_connector_source
else
    copy_sanitized_source copy-modsecurity-nginx "$MODSECURITY_NGINX_SOURCE_DIR" "$NGINX_CONNECTOR_BUILD_DIR"
    overlay_nginx_debug_header
fi
if [ -z "$MODSECURITY_SHARED_PREFIX" ]; then
    write_git_info "modsecurity-v3-build-copy" "$V3_BUILD_DIR"
fi
write_git_info "modsecurity-nginx-build-copy" "$NGINX_CONNECTOR_BUILD_DIR"

if [ -z "$MODSECURITY_SHARED_PREFIX" ]; then
    run_blocked v3-build-sh "$V3_BUILD_DIR" ./build.sh
    run_blocked v3-configure "$V3_BUILD_DIR" ./configure
    run_blocked v3-make "$V3_BUILD_DIR" make "-j$MAKE_JOBS"
fi
stage_modsecurity
build_nginx_from_source

echo "pass: nginx connector dynamic module built" >> "$STATUS_FILE"
echo "nginx_poc: pass binary=$NGINX_BINARY module=$NGINX_MODULE"
