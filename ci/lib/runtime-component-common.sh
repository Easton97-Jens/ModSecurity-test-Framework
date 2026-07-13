#!/bin/sh

# Shared runtime-component prepare helpers. The caller must source common.sh
# first; this file performs work only through explicit function calls.

runtime_component_sha_status() {
    rc_sha=$1
    if [ -n "$rc_sha" ] && [ "$rc_sha" != "TODO_PIN_SHA256" ]; then
        printf '%s\n' pinned
    else
        printf '%s\n' missing
    fi
}

write_prepare_blocked_message() {
    rc_name=$1
    rc_version=$2
    rc_source_url=$3
    rc_install_docs=$4
    rc_latest_url=$5
    rc_download_url=$6
    rc_sha_status=$7
    rc_sha_url=$8
    rc_expected_binary=$9
    rc_extra=${10:-}

    {
        printf 'BLOCKED: %s runtime dependency is not staged locally.\n' "$rc_name"
        printf 'Version: %s\n' "$rc_version"
        printf 'Source URL: %s\n' "$rc_source_url"
        if [ -n "$rc_install_docs" ]; then
            printf 'Install docs: %s\n' "$rc_install_docs"
        fi
        if [ -n "$rc_latest_url" ]; then
            printf 'Latest URL: %s\n' "$rc_latest_url"
        fi
        printf 'Download URL: %s\n' "$rc_download_url"
        printf 'SHA256 status: %s\n' "$rc_sha_status"
        printf 'SHA256 URL: %s\n' "$rc_sha_url"
        printf 'Expected local binary: %s\n' "$rc_expected_binary"
        if [ -n "$rc_extra" ]; then
            printf '%s\n' "$rc_extra"
        fi
        printf 'No global installation or unverified download was attempted.\n'
        printf 'Set ALLOW_RUNTIME_DOWNLOADS=1 to allow pinned local download and staging.\n'
    } >&2
    return 77
}

require_runtime_download_opt_in() {
    if [ "${ALLOW_RUNTIME_DOWNLOADS:-0}" = "1" ]; then
        return 0
    fi
    ci_blocked "runtime component download requires ALLOW_RUNTIME_DOWNLOADS=1"
    return 77
}

require_pinned_runtime_source() {
    rc_name=$1
    rc_version=$2
    rc_source_url=$3
    rc_download_url=$4
    rc_sha256=$5

    if [ -z "$rc_version" ] || [ "$rc_version" = "TODO_PIN_VERSION" ]; then
        ci_blocked "$rc_name version is not pinned"
        return 77
    fi
    ci_require_https_url "$rc_source_url" "$rc_name source url" || return 77
    ci_require_https_url "$rc_download_url" "$rc_name download url" || return 77
    if [ -z "$rc_sha256" ] || [ "$rc_sha256" = "TODO_PIN_SHA256" ]; then
        ci_blocked "$rc_name SHA256 is not pinned"
        return 77
    fi
    if ! printf '%s\n' "$rc_sha256" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
        ci_blocked "$rc_name SHA256 is not a 64-character hex digest"
        return 77
    fi
    return 0
}

runtime_component_require_under_cache() {
    rc_path=$1
    rc_label=${2:-runtime component path}
    ci_require_absolute_path "$rc_path" "$rc_label" || return 77
    assert_safe_runtime_path "$CONNECTOR_COMPONENT_CACHE" CONNECTOR_COMPONENT_CACHE || return 77
    case "$rc_path" in
        "$CONNECTOR_COMPONENT_CACHE"|"$CONNECTOR_COMPONENT_CACHE"/*)
            return 0
            ;;
        *)
            ci_blocked "$rc_label must be under CONNECTOR_COMPONENT_CACHE: $rc_path"
            return 77
            ;;
    esac
}

download_runtime_artifact() {
    rc_name=$1
    rc_url=$2
    rc_dest=$3
    rc_dest_dir=$(dirname "$rc_dest")
    rc_tmp="$rc_dest.tmp.$$"

    ci_require_https_url "$rc_url" "$rc_name download url" || return 77
    runtime_component_require_under_cache "$rc_dest" "$rc_name download destination" || return 77
    assert_safe_runtime_path "$rc_dest_dir" "$rc_name download directory" || return 77
    command -v curl >/dev/null 2>&1 || {
        ci_blocked "curl is required for runtime component downloads"
        return 77
    }

    mkdir -p "$rc_dest_dir"
    rm -f "$rc_tmp"
    if ! curl -fL --retry 3 --retry-delay 2 -o "$rc_tmp" "$rc_url"; then
        rm -f "$rc_tmp"
        ci_blocked "$rc_name download failed: $rc_url"
        return 77
    fi
    mv "$rc_tmp" "$rc_dest"
    printf '%s\n' "$rc_dest"
    return 0
}

verify_runtime_artifact_sha256() {
    rc_name=$1
    rc_expected=$2
    rc_file=$3
    rc_file_dir=$(dirname "$rc_file")
    rc_file_base=$(basename "$rc_file")

    [ -f "$rc_file" ] || {
        ci_blocked "$rc_name artifact missing: $rc_file"
        return 77
    }
    if [ -z "$rc_expected" ] || [ "$rc_expected" = "TODO_PIN_SHA256" ]; then
        ci_blocked "$rc_name SHA256 is not pinned"
        return 77
    fi
    command -v sha256sum >/dev/null 2>&1 || {
        ci_blocked "sha256sum is required before staging runtime artifacts"
        return 77
    }
    if ! (cd "$rc_file_dir" && printf '%s  %s\n' "$rc_expected" "$rc_file_base" | sha256sum -c -); then
        ci_blocked "$rc_name SHA256 verification failed: $rc_file"
        return 77
    fi
    return 0
}

stage_executable_binary() {
    rc_name=$1
    rc_src=$2
    rc_dest=$3
    rc_dest_dir=$(dirname "$rc_dest")
    rc_tmp="$rc_dest.tmp.$$"

    [ -f "$rc_src" ] || {
        ci_blocked "$rc_name source binary missing: $rc_src"
        return 77
    }
    runtime_component_require_under_cache "$rc_dest" "$rc_name staged binary" || return 77
    assert_safe_runtime_path "$rc_dest_dir" "$rc_name staged binary directory" || return 77

    mkdir -p "$rc_dest_dir"
    rm -f "$rc_tmp"
    cp "$rc_src" "$rc_tmp"
    chmod +x "$rc_tmp"
    mv "$rc_tmp" "$rc_dest"
    if [ ! -f "$rc_dest" ] || [ ! -x "$rc_dest" ]; then
        ci_blocked "$rc_name staged binary is not executable: $rc_dest"
        return 77
    fi
    printf '%s\n' "$rc_dest"
    return 0
}

runtime_component_tar_list() {
    rc_archive=$1
    case "$rc_archive" in
        *.tar.gz|*.tgz) tar -tzf "$rc_archive" ;;
        *.tar.xz|*.txz) tar -tJf "$rc_archive" ;;
        *)
            ci_blocked "unsupported archive format: $rc_archive"
            return 77
            ;;
    esac
}

runtime_component_tar_extract_member() {
    rc_archive=$1
    rc_extract_root=$2
    rc_member=${3:-}
    case "$rc_archive" in
        *.tar.gz|*.tgz)
            if [ -n "$rc_member" ]; then
                tar -xzf "$rc_archive" -C "$rc_extract_root" "$rc_member"
            else
                tar -xzf "$rc_archive" -C "$rc_extract_root"
            fi
            ;;
        *.tar.xz|*.txz)
            if [ -n "$rc_member" ]; then
                tar -xJf "$rc_archive" -C "$rc_extract_root" "$rc_member"
            else
                tar -xJf "$rc_archive" -C "$rc_extract_root"
            fi
            ;;
        *)
            ci_blocked "unsupported archive format: $rc_archive"
            return 77
            ;;
    esac
}

extract_single_binary_from_tar() {
    rc_name=$1
    rc_archive=$2
    rc_binary_name=$3
    rc_extract_root=$4
    rc_member_list="$rc_extract_root.members"

    [ -f "$rc_archive" ] || {
        ci_blocked "$rc_name archive missing: $rc_archive"
        return 77
    }
    runtime_component_require_under_cache "$rc_extract_root" "$rc_name extract root" || return 77
    assert_safe_runtime_path "$rc_extract_root" "$rc_name extract root" || return 77
    command -v tar >/dev/null 2>&1 || {
        ci_blocked "tar is required to extract runtime archives"
        return 77
    }

    rm -rf "$rc_extract_root"
    mkdir -p "$rc_extract_root"
    runtime_component_tar_list "$rc_archive" > "$rc_member_list" || return 77
    if grep -Eq '(^/|(^|/)\.\.(/|$))' "$rc_member_list"; then
        ci_blocked "$rc_name archive contains unsafe paths"
        return 77
    fi
    rc_member=$(awk -F/ -v binary="$rc_binary_name" '$NF == binary { print }' "$rc_member_list")
    rc_count=$(printf '%s\n' "$rc_member" | sed '/^$/d' | wc -l | tr -d ' ')
    if [ "$rc_count" != "1" ]; then
        ci_blocked "$rc_name archive must contain exactly one $rc_binary_name binary"
        return 77
    fi
    runtime_component_tar_extract_member "$rc_archive" "$rc_extract_root" "$rc_member" || return 77
    rc_extracted="$rc_extract_root/$rc_member"
    [ -f "$rc_extracted" ] || {
        ci_blocked "$rc_name extracted binary missing: $rc_extracted"
        return 77
    }
    printf '%s\n' "$rc_extracted"
    return 0
}

extract_runtime_source_tar() {
    rc_name=$1
    rc_archive=$2
    rc_source_parent=$3
    rc_expected_dirname=$4
    rc_member_list="$rc_source_parent.members"

    [ -f "$rc_archive" ] || {
        ci_blocked "$rc_name source archive missing: $rc_archive"
        return 77
    }
    runtime_component_require_under_cache "$rc_source_parent" "$rc_name source parent" || return 77
    assert_safe_runtime_path "$rc_source_parent" "$rc_name source parent" || return 77
    command -v tar >/dev/null 2>&1 || {
        ci_blocked "tar is required to extract runtime source archives"
        return 77
    }

    mkdir -p "$rc_source_parent"
    runtime_component_tar_list "$rc_archive" > "$rc_member_list" || return 77
    if grep -Eq '(^/|(^|/)\.\.(/|$))' "$rc_member_list"; then
        ci_blocked "$rc_name source archive contains unsafe paths"
        return 77
    fi
    runtime_component_tar_extract_member "$rc_archive" "$rc_source_parent" || return 77
    if [ ! -d "$rc_source_parent/$rc_expected_dirname" ]; then
        ci_blocked "$rc_name expected source directory missing after extract: $rc_source_parent/$rc_expected_dirname"
        return 77
    fi
    printf '%s\n' "$rc_source_parent/$rc_expected_dirname"
    return 0
}
