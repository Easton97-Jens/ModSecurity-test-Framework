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
    return 0
}

runtime_component_url_host() {
    rc_url=$1
    ci_safe_url_host "$rc_url"
    return $?
}

runtime_component_safe_diagnostic_value() {
    rc_value=$1
    printf '%s' "$rc_value" | tr -c 'A-Za-z0-9._:-' '_'
    return $?
}

runtime_component_artifact_id() {
    rc_artifact=${1:-none}
    if [ "$rc_artifact" = none ]; then
        printf '%s\n' none
        return 0
    fi
    rc_artifact_base=$(basename "$rc_artifact")
    printf 'cleaned:%s\n' "$(runtime_component_safe_diagnostic_value "$rc_artifact_base")"
}

runtime_component_diagnostic() {
    rc_name=$1
    rc_phase=$2
    rc_reason_code=$3
    rc_artifact=${4:-none}
    rc_url=${5:-}
    rc_bytes=${6:-0}
    rc_http_status=${7:-not_available}
    rc_redirects=${8:-not_available}
    rc_duration=${9:-not_available}
    rc_remediation=${10:-stage_a_pinned_verified_artifact}
    rc_tls_verification=${11:-not_attempted}
    rc_host=none
    if [ -n "$rc_url" ]; then
        rc_host=$(runtime_component_url_host "$rc_url")
    fi
    printf 'runtime_diagnostic{component=%s;phase=%s;status=BLOCKED;reason_code=%s;exit_code=77;http_status=%s;redirects=%s;bytes=%s;duration_s=%s;tls_verification=%s;url_host=%s;artifact_id=%s;remediation=%s}\n' \
        "$(runtime_component_safe_diagnostic_value "$rc_name")" \
        "$(runtime_component_safe_diagnostic_value "$rc_phase")" \
        "$(runtime_component_safe_diagnostic_value "$rc_reason_code")" \
        "$(runtime_component_safe_diagnostic_value "$rc_http_status")" \
        "$(runtime_component_safe_diagnostic_value "$rc_redirects")" \
        "$(runtime_component_safe_diagnostic_value "$rc_bytes")" \
        "$(runtime_component_safe_diagnostic_value "$rc_duration")" \
        "$(runtime_component_safe_diagnostic_value "$rc_tls_verification")" \
        "$(runtime_component_safe_diagnostic_value "$rc_host")" \
        "$(runtime_component_artifact_id "$rc_artifact")" \
        "$(runtime_component_safe_diagnostic_value "$rc_remediation")" >&2
    return $?
}

runtime_component_read_download_metrics() {
    rc_metrics=$1
    RUNTIME_COMPONENT_HTTP_STATUS=not_available
    RUNTIME_COMPONENT_REDIRECTS=not_available
    RUNTIME_COMPONENT_BYTES=0
    RUNTIME_COMPONENT_DURATION=not_available
    if [ -s "$rc_metrics" ]; then
        IFS='|' read -r RUNTIME_COMPONENT_HTTP_STATUS RUNTIME_COMPONENT_REDIRECTS RUNTIME_COMPONENT_BYTES RUNTIME_COMPONENT_DURATION < "$rc_metrics" || true
    fi
    return 0
}

runtime_component_curl_failure_reason() {
    rc_exit_code=$1
    rc_http_status=$2
    case "$rc_exit_code" in
        6) printf '%s\n' dns_resolution_failed ;;
        7) printf '%s\n' connect_failed ;;
        28) printf '%s\n' transfer_timeout ;;
        35|51|53|58|59|60|77|83) printf '%s\n' tls_verification_failed ;;
        22)
            case "$rc_http_status" in
                403) printf '%s\n' http_403 ;;
                404) printf '%s\n' http_404 ;;
                429) printf '%s\n' http_429 ;;
                500) printf '%s\n' http_500 ;;
                503) printf '%s\n' http_503 ;;
                *) printf '%s\n' http_failure ;;
            esac
            ;;
        *) printf '%s\n' curl_failed ;;
    esac
    return $?
}

runtime_component_curl_remediation() {
    rc_reason=$1
    case "$rc_reason" in
        dns_resolution_failed|connect_failed|transfer_timeout|http_429|http_500|http_503)
            printf '%s\n' retry_after_repairing_transient_network_or_service_state
            ;;
        tls_verification_failed)
            printf '%s\n' restore_trusted_tls_configuration_without_disabling_verification
            ;;
        http_403|http_404)
            printf '%s\n' correct_reviewed_release_metadata_or_access
            ;;
        *)
            printf '%s\n' inspect_safe_download_diagnostics
            ;;
    esac
    return $?
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
        printf 'Source URL host: %s\n' "$(runtime_component_url_host "$rc_source_url")"
        if [ -n "$rc_install_docs" ]; then
            printf 'Install docs host: %s\n' "$(runtime_component_url_host "$rc_install_docs")"
        fi
        if [ -n "$rc_latest_url" ]; then
            printf 'Latest URL host: %s\n' "$(runtime_component_url_host "$rc_latest_url")"
        fi
        printf 'Download URL host: %s\n' "$(runtime_component_url_host "$rc_download_url")"
        printf 'SHA256 status: %s\n' "$rc_sha_status"
        printf 'SHA256 URL host: %s\n' "$(runtime_component_url_host "$rc_sha_url")"
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

runtime_component_require_locked_profile() {
    rc_lock_profile=$1
    rc_lock_version=$2
    rc_lock_download_url=$3
    rc_lock_sha256=$4
    rc_lock_python=$(ci_python)
    "$rc_lock_python" "$CI_ROOT/tools/check-runtime-component-lock.py" \
        --lock "$CI_ROOT/provisioning/runtime-component-lock.json" \
        --common "$CI_ROOT/lib/common.sh" \
        --manifest "$CI_ROOT/provisioning/runtime-components.manifest.json" \
        --environment-profile "$rc_lock_profile" \
        --environment-value "$rc_lock_version" \
        --environment-value "$rc_lock_download_url" \
        --environment-value "$rc_lock_sha256"
    return $?
}

runtime_component_require_under_root() {
    rc_path=$1
    rc_root=$2
    rc_label=${3:-runtime component path}
    ci_require_absolute_path "$rc_path" "$rc_label" || return 77
    assert_safe_runtime_path "$rc_root" "${rc_label}_root" || return 77
    assert_runtime_path_under_root "$rc_path" "$rc_root" "$rc_label" || return 77
    return 0
}

runtime_component_require_under_cache() {
    rc_path=$1
    rc_label=${2:-runtime component path}
    runtime_component_require_under_root "$rc_path" "$CONNECTOR_COMPONENT_CACHE" "$rc_label" || return 77
    return 0
}

# Write small, cache-local provenance metadata without following a pre-existing
# final symlink.  The target is replaced atomically only after its root and
# final entry have been checked; the temporary file is private and created in
# the target directory so the rename cannot cross a filesystem boundary.
# Content is read from standard input.
runtime_component_write_provenance_file() (
    rc_provenance_target=${1:-}
    rc_provenance_root=${2:-}
    rc_provenance_label=${3:-runtime provenance file}
    rc_provenance_dir=
    rc_provenance_base=
    rc_provenance_tmp=

    if [ "$#" -ne 3 ]; then
        ci_blocked "runtime provenance writer requires target, root, and label"
        return 77
    fi
    runtime_component_require_under_root \
        "$rc_provenance_target" "$rc_provenance_root" "$rc_provenance_label" || return 77
    rc_provenance_dir=$(dirname "$rc_provenance_target")
    runtime_component_require_under_root \
        "$rc_provenance_dir" "$rc_provenance_root" "$rc_provenance_label directory" || return 77
    if [ -L "$rc_provenance_target" ]; then
        ci_blocked "$rc_provenance_label must not be a symlink: $rc_provenance_target"
        return 77
    fi
    if [ -e "$rc_provenance_target" ] && [ ! -f "$rc_provenance_target" ]; then
        ci_blocked "$rc_provenance_label must be a regular file when it exists: $rc_provenance_target"
        return 77
    fi
    command -v mktemp >/dev/null 2>&1 || {
        ci_blocked "mktemp is required for safe runtime provenance writes"
        return 77
    }
    mkdir -p "$rc_provenance_dir" || {
        ci_blocked "cannot create $rc_provenance_label directory: $rc_provenance_dir"
        return 77
    }
    rc_provenance_base=$(basename "$rc_provenance_target")
    umask 077
    rc_provenance_tmp=$(mktemp "$rc_provenance_dir/.${rc_provenance_base}.tmp.XXXXXX") || {
        ci_blocked "cannot create private $rc_provenance_label staging file"
        return 77
    }
    trap 'rm -f "$rc_provenance_tmp"' 0 HUP INT TERM
    if ! cat > "$rc_provenance_tmp"; then
        ci_blocked "cannot write $rc_provenance_label staging file"
        return 77
    fi
    if [ ! -f "$rc_provenance_tmp" ] || [ -L "$rc_provenance_tmp" ]; then
        ci_blocked "$rc_provenance_label staging file is not regular"
        return 77
    fi
    # A race that swaps in a symlink after the first check is still safe: mv
    # replaces the directory entry rather than writing through its target.
    if [ -L "$rc_provenance_target" ]; then
        ci_blocked "$rc_provenance_label became a symlink before staging"
        return 77
    fi
    if ! mv -f "$rc_provenance_tmp" "$rc_provenance_target"; then
        ci_blocked "cannot atomically publish $rc_provenance_label"
        return 77
    fi
    if [ ! -f "$rc_provenance_target" ] || [ -L "$rc_provenance_target" ]; then
        ci_blocked "$rc_provenance_label was not published as a regular file"
        return 77
    fi
    return 0
)

runtime_component_require_bounded_timeout() {
    rc_timeout_value=$1
    rc_timeout_name=$2
    rc_timeout_maximum=$3
    if ! printf '%s\n' "$rc_timeout_value" | grep -Eq '^[1-9][0-9]*$'; then
        ci_blocked "$rc_timeout_name must be a positive bounded integer"
        return 77
    fi
    if [ "$rc_timeout_value" -gt "$rc_timeout_maximum" ]; then
        ci_blocked "$rc_timeout_name exceeds the reviewed timeout bound"
        return 77
    fi
    return 0
}

runtime_component_validate_download_timeouts() {
    RUNTIME_COMPONENT_DOWNLOAD_CONNECT_TIMEOUT=${RUNTIME_DOWNLOAD_CONNECT_TIMEOUT:-10}
    RUNTIME_COMPONENT_DOWNLOAD_MAX_TIME=${RUNTIME_DOWNLOAD_MAX_TIME:-300}
    RUNTIME_COMPONENT_DOWNLOAD_RETRY_MAX_TIME=${RUNTIME_DOWNLOAD_RETRY_MAX_TIME:-60}

    runtime_component_require_bounded_timeout \
        "$RUNTIME_COMPONENT_DOWNLOAD_CONNECT_TIMEOUT" \
        RUNTIME_DOWNLOAD_CONNECT_TIMEOUT 60 || return 77
    runtime_component_require_bounded_timeout \
        "$RUNTIME_COMPONENT_DOWNLOAD_MAX_TIME" \
        RUNTIME_DOWNLOAD_MAX_TIME 900 || return 77
    runtime_component_require_bounded_timeout \
        "$RUNTIME_COMPONENT_DOWNLOAD_RETRY_MAX_TIME" \
        RUNTIME_DOWNLOAD_RETRY_MAX_TIME 300 || return 77
    if [ "$RUNTIME_COMPONENT_DOWNLOAD_RETRY_MAX_TIME" -gt "$RUNTIME_COMPONENT_DOWNLOAD_MAX_TIME" ]; then
        ci_blocked "RUNTIME_DOWNLOAD_RETRY_MAX_TIME must not exceed RUNTIME_DOWNLOAD_MAX_TIME"
        return 77
    fi
    return 0
}

runtime_component_curl_download() {
    rc_curl_tmp=$1
    rc_curl_url=$2
    rc_curl_max_redirects=${3:-}
    if [ -n "$rc_curl_max_redirects" ]; then
        curl --disable --proto =https --proto-redir =https -fL --connect-timeout "$RUNTIME_COMPONENT_DOWNLOAD_CONNECT_TIMEOUT" \
            --max-time "$RUNTIME_COMPONENT_DOWNLOAD_MAX_TIME" \
            --retry 3 --retry-delay 2 --retry-max-time "$RUNTIME_COMPONENT_DOWNLOAD_RETRY_MAX_TIME" \
            --max-redirs "$rc_curl_max_redirects" \
            --write-out '%{http_code}|%{num_redirects}|%{size_download}|%{time_total}\n' \
            -o "$rc_curl_tmp" "$rc_curl_url"
        return $?
    fi
    curl --disable --proto =https --proto-redir =https -fL --connect-timeout "$RUNTIME_COMPONENT_DOWNLOAD_CONNECT_TIMEOUT" \
        --max-time "$RUNTIME_COMPONENT_DOWNLOAD_MAX_TIME" \
        --retry 3 --retry-delay 2 --retry-max-time "$RUNTIME_COMPONENT_DOWNLOAD_RETRY_MAX_TIME" \
        --write-out '%{http_code}|%{num_redirects}|%{size_download}|%{time_total}\n' \
        -o "$rc_curl_tmp" "$rc_curl_url"
}

download_runtime_artifact_under_root() {
    rc_name=$1
    rc_url=$2
    rc_dest=$3
    rc_root=$4
    rc_dest_dir=$(dirname "$rc_dest")
    rc_dest_base=$(basename "$rc_dest")
    rc_tmp=
    rc_metrics=
    rc_max_redirects=${5:-}

    ci_require_https_url "$rc_url" "$rc_name download url" || return 77
    if [ -n "$rc_max_redirects" ] && ! printf '%s\n' "$rc_max_redirects" | grep -Eq '^[0-9]+$'; then
        runtime_component_diagnostic "$rc_name" download redirect_limit_invalid "$rc_dest" "$rc_url" 0 not_available not_available not_available "provide_a_nonnegative_redirect_limit" not_attempted
        return 77
    fi
    if ! runtime_component_validate_download_timeouts; then
        runtime_component_diagnostic "$rc_name" download timeout_policy_invalid "$rc_dest" "$rc_url" 0 not_available not_available not_available "set_positive_bounded_download_timeouts" not_attempted
        return 77
    fi
    runtime_component_require_under_root "$rc_dest" "$rc_root" "$rc_name download destination" || return 77
    assert_safe_runtime_path "$rc_dest_dir" "$rc_name download directory" || return 77
    command -v curl >/dev/null 2>&1 || {
        ci_blocked "curl is required for runtime component downloads"
        return 77
    }
    command -v mktemp >/dev/null 2>&1 || {
        ci_blocked "mktemp is required for safe runtime component downloads"
        return 77
    }

    mkdir -p "$rc_dest_dir"
    rc_tmp=$(mktemp "$rc_dest_dir/.${rc_dest_base}.download.XXXXXX") || {
        runtime_component_diagnostic "$rc_name" download temporary_artifact_unavailable "$rc_dest" "$rc_url" 0 not_available not_available not_available "repair_runtime_cache_permissions" not_attempted
        return 77
    }
    rc_metrics=$(mktemp "$rc_dest_dir/.${rc_dest_base}.metrics.XXXXXX") || {
        rm -f "$rc_tmp"
        runtime_component_diagnostic "$rc_name" download temporary_metrics_unavailable "$rc_dest" "$rc_url" 0 not_available not_available not_available "repair_runtime_cache_permissions" not_attempted
        return 77
    }
    rm -f "$rc_dest"
    if (
        trap 'rm -f "$rc_tmp" "$rc_metrics"; exit 77' HUP INT TERM
        runtime_component_curl_download "$rc_tmp" "$rc_url" "$rc_max_redirects" >"$rc_metrics" 2>/dev/null
    ); then
        rc_curl_exit=0
    else
        rc_curl_exit=$?
        runtime_component_read_download_metrics "$rc_metrics"
        rc_reason=$(runtime_component_curl_failure_reason "$rc_curl_exit" "$RUNTIME_COMPONENT_HTTP_STATUS")
        rc_remediation=$(runtime_component_curl_remediation "$rc_reason")
        case "$rc_reason" in
            tls_verification_failed) rc_tls_verification=failed ;;
            http_*) rc_tls_verification=verified ;;
            *) rc_tls_verification=not_confirmed ;;
        esac
        rm -f "$rc_tmp" "$rc_dest"
        runtime_component_diagnostic "$rc_name" download "$rc_reason" "$rc_dest" "$rc_url" "$RUNTIME_COMPONENT_BYTES" "$RUNTIME_COMPONENT_HTTP_STATUS" "$RUNTIME_COMPONENT_REDIRECTS" "$RUNTIME_COMPONENT_DURATION" "$rc_remediation" "$rc_tls_verification"
        rm -f "$rc_metrics"
        ci_blocked "$rc_name download failed (host=$(runtime_component_url_host "$rc_url"))"
        return 77
    fi
    runtime_component_read_download_metrics "$rc_metrics"
    rm -f "$rc_metrics"
    if [ ! -s "$rc_tmp" ]; then
        rm -f "$rc_tmp" "$rc_dest"
        runtime_component_diagnostic "$rc_name" download empty_artifact "$rc_dest" "$rc_url" "$RUNTIME_COMPONENT_BYTES" "$RUNTIME_COMPONENT_HTTP_STATUS" "$RUNTIME_COMPONENT_REDIRECTS" "$RUNTIME_COMPONENT_DURATION" "use_a_nonempty_verified_release_asset" verified
        ci_blocked "$rc_name download produced an empty artifact"
        return 77
    fi
    if ! mv "$rc_tmp" "$rc_dest"; then
        rm -f "$rc_tmp" "$rc_dest"
        runtime_component_diagnostic "$rc_name" download artifact_stage_failed "$rc_dest" "$rc_url" "$RUNTIME_COMPONENT_BYTES" "$RUNTIME_COMPONENT_HTTP_STATUS" "$RUNTIME_COMPONENT_REDIRECTS" "$RUNTIME_COMPONENT_DURATION" "repair_runtime_cache_permissions" verified
        ci_blocked "$rc_name download could not stage the artifact"
        return 77
    fi
    printf '%s\n' "$rc_dest"
    return 0
}

download_runtime_artifact_without_redirects_under_root() {
    rc_no_redirect_name=$1
    rc_no_redirect_url=$2
    rc_no_redirect_dest=$3
    rc_no_redirect_root=$4
    download_runtime_artifact_under_root "$rc_no_redirect_name" "$rc_no_redirect_url" "$rc_no_redirect_dest" "$rc_no_redirect_root" 0
    return $?
}

download_runtime_artifact() {
    rc_name=$1
    rc_url=$2
    rc_dest=$3
    download_runtime_artifact_under_root "$rc_name" "$rc_url" "$rc_dest" "$CONNECTOR_COMPONENT_CACHE"
    return $?
}

verify_runtime_artifact_sha256() {
    rc_name=$1
    rc_expected=$2
    rc_file=$3

    [ -f "$rc_file" ] && [ -s "$rc_file" ] || {
        rm -f "$rc_file"
        runtime_component_diagnostic "$rc_name" verify missing_or_empty "$rc_file" "" 0 not_available not_available not_available "stage_a_nonempty_verified_artifact" not_attempted
        ci_blocked "$rc_name artifact missing or empty"
        return 77
    }
    if [ -z "$rc_expected" ] || [ "$rc_expected" = "TODO_PIN_SHA256" ]; then
        rm -f "$rc_file"
        runtime_component_diagnostic "$rc_name" verify sha256_missing "$rc_file" "" 0 not_available not_available not_available "provide_a_reviewed_sha256_pin" not_attempted
        ci_blocked "$rc_name SHA256 is not pinned"
        return 77
    fi
    if ! printf '%s\n' "$rc_expected" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
        rm -f "$rc_file"
        runtime_component_diagnostic "$rc_name" verify sha256_invalid "$rc_file" "" 0 not_available not_available not_available "provide_a_64_character_sha256_pin" not_attempted
        ci_blocked "$rc_name SHA256 is not a 64-character hex digest"
        return 77
    fi
    rc_actual=$(ci_trusted_sha256_file "$rc_file") || {
        rm -f "$rc_file"
        runtime_component_diagnostic "$rc_name" verify sha256_verification_unavailable "$rc_file" "" 0 not_available not_available not_available "provide_a_trusted_sha256sum_before_staging" not_attempted
        ci_blocked "$rc_name SHA256 verification could not use the trusted system tool"
        return 77
    }
    if [ "$rc_actual" != "$rc_expected" ]; then
        rm -f "$rc_file"
        runtime_component_diagnostic "$rc_name" verify sha256_mismatch "$rc_file" "" 0 not_available not_available not_available "replace_with_the_pinned_verified_artifact" not_attempted
        ci_blocked "$rc_name SHA256 verification failed"
        return 77
    fi
    return 0
}

# Freeze a verified archive into a task-local path before extraction. A shared
# component-cache writer may replace the source after its first digest check;
# the private copy is rehashed and is the only archive returned to callers.
runtime_component_stage_verified_archive() {
    rc_name=$1
    rc_expected=$2
    rc_source=$3
    rc_destination=$4
    rc_root=$5
    rc_destination_dir=$(dirname "$rc_destination")
    rc_destination_base=$(basename "$rc_destination")
    rc_tmp=

    runtime_component_require_under_root "$rc_destination" "$rc_root" "$rc_name verified archive" || return 77
    [ -f "$rc_source" ] && [ ! -L "$rc_source" ] || {
        ci_blocked "$rc_name source archive is not a regular file: $rc_source"
        return 77
    }
    verify_runtime_artifact_sha256 "$rc_name" "$rc_expected" "$rc_source" || return 77
    mkdir -p "$rc_destination_dir" || {
        ci_blocked "cannot create $rc_name verified archive directory: $rc_destination_dir"
        return 77
    }
    command -v mktemp >/dev/null 2>&1 || {
        ci_blocked "mktemp is required for a private $rc_name verified archive"
        return 77
    }
    umask 077
    rc_tmp=$(mktemp "$rc_destination_dir/.${rc_destination_base}.tmp.XXXXXX") || {
        ci_blocked "cannot create private $rc_name verified archive staging file"
        return 77
    }
    trap 'rm -f "$rc_tmp"' 0 HUP INT TERM
    if ! cp "$rc_source" "$rc_tmp"; then
        ci_blocked "could not copy $rc_name archive into the private build root"
        return 77
    fi
    [ -f "$rc_tmp" ] && [ ! -L "$rc_tmp" ] || {
        ci_blocked "$rc_name private archive staging file is not regular"
        return 77
    }
    verify_runtime_artifact_sha256 "$rc_name" "$rc_expected" "$rc_tmp" || return 77
    if [ -L "$rc_destination" ]; then
        ci_blocked "$rc_name verified archive destination must not be a symlink: $rc_destination"
        return 77
    fi
    mv -f "$rc_tmp" "$rc_destination" || {
        ci_blocked "could not publish private $rc_name verified archive"
        return 77
    }
    verify_runtime_artifact_sha256 "$rc_name" "$rc_expected" "$rc_destination" || return 77
    trap - 0 HUP INT TERM
    printf '%s\n' "$rc_destination"
    return 0
}

stage_executable_binary() {
    rc_name=$1
    rc_src=$2
    rc_dest=$3
    rc_dest_root=${4:-$CONNECTOR_COMPONENT_CACHE}
    rc_dest_dir=$(dirname "$rc_dest")
    rc_tmp="$rc_dest.tmp.$$"

    [ -f "$rc_src" ] || {
        ci_blocked "$rc_name source binary missing: $rc_src"
        return 77
    }
    runtime_component_require_under_root "$rc_dest" "$rc_dest_root" "$rc_name staged binary" || return 77
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
    rc_extract_root_base=${5:-$CONNECTOR_COMPONENT_CACHE}
    rc_member_list="$rc_extract_root.members"

    [ -f "$rc_archive" ] || {
        ci_blocked "$rc_name archive missing: $rc_archive"
        return 77
    }
    runtime_component_require_under_root "$rc_extract_root" "$rc_extract_root_base" "$rc_name extract root" || return 77
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
    rc_source_root=${5:-$CONNECTOR_COMPONENT_CACHE}
    rc_member_list="$rc_source_parent.members"

    [ -f "$rc_archive" ] || {
        ci_blocked "$rc_name source archive missing: $rc_archive"
        return 77
    }
    runtime_component_require_under_root "$rc_source_parent" "$rc_source_root" "$rc_name source parent" || return 77
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
