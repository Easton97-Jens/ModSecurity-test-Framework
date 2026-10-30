#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
PYTHONSAFEPATH=1
PYTHONNOUSERSITE=1
export PYTHONPATH PYTHONSAFEPATH PYTHONNOUSERSITE
[ -d "$FRAMEWORK_ROOT" ] || { echo "apache_smoke: blocked FRAMEWORK_ROOT is missing; run git submodule update --init --recursive or set FRAMEWORK_ROOT=/path/to/ModSecurity-test-Framework"; exit 77; }
BUILD_ROOT="${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}"
APACHE_BUILD_ROOT="${APACHE_BUILD_ROOT:-$BUILD_ROOT/apache-build}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/apache-runtime}"
RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
if [ -n "${FORCE_ALL_CASES:-}" ] && [ "$RESULTS_DIR" = "$BUILD_ROOT/results" ]; then
    RESULTS_DIR="$BUILD_ROOT/results/force-all"
fi
APACHE_CASE_OUTPUT_ROOT="${APACHE_CASE_OUTPUT_ROOT:-$BUILD_ROOT}"
RUNTIME_BASE="${RUNTIME_BASE:-$BUILD_ROOT/apache-runtime}"
RUNTIME_ROOT="${RUNTIME_ROOT:-}"
HTTPD_PREFIX="${HTTPD_PREFIX:-$BUILD_ROOT/apache-runtime/httpd}"
MODSECURITY_V3_DIR="${MODSECURITY_V3_DIR:-$APACHE_BUILD_ROOT/ModSecurity_V3}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-$APACHE_BUILD_ROOT/output/modsecurity/lib}"
PCRE2_PREFIX="${PCRE2_PREFIX:-$APACHE_BUILD_ROOT/output/pcre2}"
APACHE_MODULE="${APACHE_MODULE:-$APACHE_BUILD_ROOT/output/apache/mod_security3.so}"
APACHE_HTTPD_BIN="${APACHE_HTTPD:-${APACHE:-$HTTPD_PREFIX/bin/httpd}}"
APXS_BIN="${APXS:-$HTTPD_PREFIX/bin/apxs}"
CURL_BIN="${CURL:-}"
PYTHON_BIN="${PYTHON:-python3}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
RESULT_RUN_ID=${NO_CRS_RUN_ID:-${SMOKE_RUN_ID:-${VERIFIED_RUN_ID:-}}}
: "${RESULT_RUN_ID:?an explicit NO_CRS_RUN_ID, SMOKE_RUN_ID or VERIFIED_RUN_ID is required}"
SMOKE_RUN_ID=$RESULT_RUN_ID
export SMOKE_RUN_ID

APACHE_PROCESS_GUARD="$SCRIPT_DIR/apache_process_guard.py"
SETSID_BIN="${SETSID:-setsid}"
RECORD_FAILURE_CLEANED_EXIT=74
HTTPD_RECORD_FAILURE_CLEANED=0
HTTPD_SUPERVISOR_STATE=""
HTTPD_SUPERVISOR_PID_OUTPUT=""
HTTPD_SUPERVISOR_PID=""
PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export PYTHONDONTWRITEBYTECODE
BASE_PORT="${PORT:-18080}"
PORT="$BASE_PORT"
PORT_SEARCH_LIMIT="${PORT_SEARCH_LIMIT:-100}"
PORT_RETRY_LIMIT="${PORT_RETRY_LIMIT:-1}"
TEMPLATE="$SCRIPT_DIR/apache_smoke.conf"
TEST_CASE="${TEST_CASE:-}"
SMOKE_CASES="${SMOKE_CASES:-}"
CASE_SCOPE="${CASE_SCOPE:-all}"
CASE_CLI="$FRAMEWORK_ROOT/tests/runners/case_cli.py"
RUN_ONE_CASE="${RUN_ONE_CASE:-0}"
MSCONNECTOR_SMOKE_STAGE="${MSCONNECTOR_SMOKE_STAGE:-minimal_runtime_smoke}"
STATUS_FILE="$LOG_DIR/status.txt"
IFMODULE_END="</IfModule>"
CONNECTOR_ORIGIN_SOURCE="${CONNECTOR_ORIGIN_SOURCE:-}"
CONNECTOR_ORIGIN_SOURCE_REPO="${CONNECTOR_ORIGIN_SOURCE_REPO:-}"
CONNECTOR_ORIGIN_SOURCE_URL="${CONNECTOR_ORIGIN_SOURCE_URL:-}"
CONNECTOR_ORIGIN_SOURCE_COMMIT="${CONNECTOR_ORIGIN_SOURCE_COMMIT:-}"
CONNECTOR_ORIGIN_SOURCE_VERSION="${CONNECTOR_ORIGIN_SOURCE_VERSION:-}"
CONNECTOR_ORIGIN_LICENSE="${CONNECTOR_ORIGIN_LICENSE:-}"
CONNECTOR_ORIGIN_IMPORTED_PATH="${CONNECTOR_ORIGIN_IMPORTED_PATH:-}"
MODSECURITY_TEST_VARIANT="${MODSECURITY_TEST_VARIANT:-}"
MODSECURITY_RULE_PREAMBLE_FILE="${MODSECURITY_RULE_PREAMBLE_FILE:-}"
APACHE_PROFILE_CLEANUP_RECEIPT="${APACHE_PROFILE_CLEANUP_RECEIPT:-}"
APACHE_PROFILE_CELL_RUN_ID="${APACHE_PROFILE_CELL_RUN_ID:-}"
APACHE_PROFILE_GITHUB_RUN_ID="${APACHE_PROFILE_GITHUB_RUN_ID:-}"
APACHE_PROFILE_GITHUB_RUN_ATTEMPT="${APACHE_PROFILE_GITHUB_RUN_ATTEMPT:-}"
APACHE_PROFILE_FINAL_CLEANUP=0
APACHE_PROFILE_EVIDENCE_SCRIPT="$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/with-crs-no-mrts-profile.py"
MSCONNECTOR_FULL_LIFECYCLE_SYNC="${MSCONNECTOR_FULL_LIFECYCLE_SYNC:-0}"
FULL_LIFECYCLE_EVIDENCE_OUTPUT="${FULL_LIFECYCLE_EVIDENCE_OUTPUT:-}"
MSCONNECTOR_PHASE4_SYNC_EXPECTATION="${MSCONNECTOR_PHASE4_SYNC_EXPECTATION:-first_byte}"
SYNCHRONIZED_UPSTREAM="${SYNCHRONIZED_UPSTREAM:-$FRAMEWORK_ROOT/tests/runners/synchronized_upstream.py}"
APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT="${APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT:-0}"
APACHE_PHASE4_ROGUE_TEST="${APACHE_PHASE4_ROGUE_TEST:-0}"
APACHE_PHASE4_ROGUE_PROTOCOL="${APACHE_PHASE4_ROGUE_PROTOCOL:-http1}"
APACHE_PHASE4_ERROR_DOCUMENT="${APACHE_PHASE4_ERROR_DOCUMENT:-0}"
APACHE_PHASE4_ROGUE_EXPECT="${APACHE_PHASE4_ROGUE_EXPECT:-deny}"
APACHE_PHASE4_ROGUE_PHASE="${APACHE_PHASE4_ROGUE_PHASE:-p4}"
APACHE_PHASE4_ROGUE_HEADER_MUTATION="${APACHE_PHASE4_ROGUE_HEADER_MUTATION:-0}"
APACHE_PHASE4_INTERNAL_REDIRECT_TEST="${APACHE_PHASE4_INTERNAL_REDIRECT_TEST:-0}"
APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT="${APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT:-abort}"
APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST="${APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST:-0}"
APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST="${APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST:-0}"
APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST="${APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST:-0}"
APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID="${APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID:-}"
APACHE_PHASE4_DOWNSTREAM_ERROR_TEST="${APACHE_PHASE4_DOWNSTREAM_ERROR_TEST:-0}"
APACHE_PHASE4_UPSTREAM_ERROR_TEST="${APACHE_PHASE4_UPSTREAM_ERROR_TEST:-0}"
APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST="${APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST:-0}"
APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST="${APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST:-0}"
APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST="${APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST:-0}"
APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST="${APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST:-0}"
readonly APACHE_LOG_DIR_LABEL='LOG_DIR'
readonly APACHE_RESULTS_DIR_LABEL='RESULTS_DIR'
prepare_runtime_directory() {
    directory=$1
    label=$2
    private_mode=${3:-0}
    case "$private_mode" in
        0) set -- ;;
        1) set -- --private ;;
        *)
            echo "apache_smoke: blocked $label private-mode value is invalid" >&2
            return 77
            ;;
    esac
    MSCONNECTOR_APACHE_GUARD_DIRECTORY="$directory" \
        "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" prepare-directory \
        --label "$label" "$@"
}

prepare_runtime_directory "$LOG_DIR" "$APACHE_LOG_DIR_LABEL" 1
prepare_runtime_directory "$APACHE_CASE_OUTPUT_ROOT" "APACHE_CASE_OUTPUT_ROOT" 0
readonly PHASE4_FIRST_BYTE_PREFIX='first-byte-prefix'
readonly PHASE4_TRANSACTION_REBIND_REFUSAL='request transaction cannot be safely rebound to the target URI'
readonly PHASE4_RESPONSE_BODY_MARKER='no-crs-response-body-marker'
readonly APACHE_LOCATION_END='</Location>'
readonly HTTP2_PROTOCOL_LABEL='HTTP/2'
readonly CURL_H2_ALPN_ACCEPT_PATTERN='ALPN: server accepted h2|ALPN, server accepted to use h2'
OPENSSL_BIN="${OPENSSL:-openssl}"
readonly CURL_HTTP2_FEATURE_PATTERN='Features:.*HTTP2'
readonly CURL_HTTP_STATUS_FORMAT='%{http_code}'
readonly CURL_HTTP_STATUS_VERSION_FORMAT='%{http_code}\t%{http_version}\n'
readonly AWK_FIRST_TAB_RECORD_STATUS='NR == 1 { print $1; exit }'
readonly AWK_FIRST_TAB_RECORD_VERSION='NR == 1 { print $2; exit }'
readonly OBSERVED_TRANSPORT_HTTP_STATUS='http_status'

load_connector_adapter_metadata() {
    eval "$(CONNECTOR_ROOT="$REPO_ROOT" "$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/lib/adapter_metadata.py" shell apache --prefix CONNECTOR_ADAPTER)"
    CONNECTOR_ORIGIN_SOURCE="${CONNECTOR_ORIGIN_SOURCE:-$CONNECTOR_ADAPTER_SOURCE}"
    CONNECTOR_ORIGIN_SOURCE_REPO="${CONNECTOR_ORIGIN_SOURCE_REPO:-$CONNECTOR_ADAPTER_SOURCE_REPO}"
    CONNECTOR_ORIGIN_SOURCE_URL="${CONNECTOR_ORIGIN_SOURCE_URL:-$CONNECTOR_ADAPTER_SOURCE_URL}"
    CONNECTOR_ORIGIN_SOURCE_COMMIT="${CONNECTOR_ORIGIN_SOURCE_COMMIT:-$CONNECTOR_ADAPTER_SOURCE_COMMIT}"
    CONNECTOR_ORIGIN_SOURCE_VERSION="${CONNECTOR_ORIGIN_SOURCE_VERSION:-$CONNECTOR_ADAPTER_SOURCE_VERSION}"
    CONNECTOR_ORIGIN_LICENSE="${CONNECTOR_ORIGIN_LICENSE:-$CONNECTOR_ADAPTER_LICENSE}"
    CONNECTOR_ORIGIN_IMPORTED_PATH="${CONNECTOR_ORIGIN_IMPORTED_PATH:-$CONNECTOR_ADAPTER_IMPORTED_PATH}"
}

load_connector_adapter_metadata

blocked() {
    echo "apache_smoke: blocked $*"
    echo "blocked: $*" >> "$STATUS_FILE"
    exit 77
}

fail() {
    echo "apache_smoke: fail $*"
    echo "fail: $*" >> "$STATUS_FILE"
    exit 1
}

require_audit_rule() {
    audit_rule_id=$1
    audit_failure=$2
    if [ ! -s "$AUDIT_LOG_FILE" ] || \
        ! grep -F "$audit_rule_id" "$AUDIT_LOG_FILE" >/dev/null 2>&1; then
        fail "$audit_failure"
    fi
}

not_executable() {
    echo "apache_smoke: not_executable $*"
    echo "not_executable: $*" >> "$STATUS_FILE"
    exit 78
}

configtest_case_not_executable() {
    grep -E "Rules error|modsecurity-smoke\\.conf|modsecurity_rules_file|modsecurity_rules" \
        "$LOG_DIR/configtest.log" >/dev/null 2>&1
}

require_absolute_generated_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *) blocked "$label must be absolute: $path" ;;
    esac
    case "$path" in
        "$REPO_ROOT"|"$REPO_ROOT"/*|"$FRAMEWORK_ROOT"|"$FRAMEWORK_ROOT"/*)
            blocked "$label is inside a read-only or source checkout: $path"
            ;;
        *) ;;
    esac
}

resolve_case_path() {
    item=$1
    "$PYTHON_BIN" "$CASE_CLI" list-cases \
        --repo-root "$REPO_ROOT" \
        --framework-root "$FRAMEWORK_ROOT" \
        --connector-root "$REPO_ROOT" \
        --connector apache \
        --scope "$CASE_SCOPE" \
        --test-case "$item"
}

list_case_files() {
    args="--repo-root $REPO_ROOT --framework-root $FRAMEWORK_ROOT --connector-root $REPO_ROOT --connector apache --scope $CASE_SCOPE"
    if [ -n "$TEST_CASE" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --framework-root "$FRAMEWORK_ROOT" \
            --connector-root "$REPO_ROOT" \
            --connector apache \
            --scope "$CASE_SCOPE" \
            --test-case "$TEST_CASE"
        return
    fi
    if [ -n "$SMOKE_CASES" ]; then
        "$PYTHON_BIN" "$CASE_CLI" list-cases \
            --repo-root "$REPO_ROOT" \
            --framework-root "$FRAMEWORK_ROOT" \
            --connector-root "$REPO_ROOT" \
            --connector apache \
            --scope "$CASE_SCOPE" \
            --smoke-cases "$SMOKE_CASES"
        return
    fi
    # shellcheck disable=SC2086
    "$PYTHON_BIN" "$CASE_CLI" list-cases $args
}

append_smoke_case() {
    fixture=$1
    case " $SMOKE_CASES " in
        *" $fixture "*|*" $fixture.yaml "*) return 0 ;;
    esac
    SMOKE_CASES="${SMOKE_CASES}${SMOKE_CASES:+ }$fixture"
}

append_selected_phase4_fixtures() {
    # The canonical catalog names the late-intervention outcomes while the
    # Apache harness owns the real post-commit host fixtures.  Add only those
    # fixtures selected by the current plan; never manufacture a response-body
    # result from a generic request-phase case.
    case "${NO_CRS_BASELINE:-}" in
        1|true|TRUE|yes|YES|on|ON) ;;
        *) return 0 ;;
    esac
    [ "$RUN_ONE_CASE" != "1" ] || return 0
    [ -n "${NO_CRS_SELECTED_CASE_IDS:-}" ] || return 0

    set -f
    for case_id in $NO_CRS_SELECTED_CASE_IDS; do
        case "$case_id" in
            phase4_deny_after_commit_log_only)
                append_smoke_case apache_phase4_deny_after_commit_log_only
                ;;
            phase4_deny_after_commit_abort)
                append_smoke_case apache_phase4_deny_after_commit_abort
                ;;
            *[!A-Za-z0-9_]*|"")
                set +f
                blocked "unsafe canonical case id: $case_id"
                ;;
            *)
                # Other canonical IDs have catalog-owned runner fixtures or
                # remain explicitly unexecuted until a real Apache driver
                # exists for their contract.
                ;;
        esac
    done
    set +f
}

write_case_result() {
    case_path=$1
    case_status=$2
    actual_status=${3:-}
    output=$4
    observed_transport=${5:-http_status}
    reason=${6:-}
    output_dir=$(dirname "$output")
    set -- "$PYTHON_BIN" "$CASE_CLI" case-info \
        --case "$case_path" --connector apache \
        --status "$case_status" --observed-transport-result "$observed_transport" \
        --reason "$reason" --response-body-file "$output_dir/response-body.txt" \
        --audit-log-file "$output_dir/audit.log" \
        --access-log-file "$output_dir/access.log" --error-log-file "$output_dir/error.log" \
        --phase4-log-file "$output_dir/phase4.log" \
        --capture-request-log "$output_dir/phase4.log" \
        --capture-request-window "$output_dir/request-window.json" \
        --run-id "$RESULT_RUN_ID" --source-revision "$CONNECTOR_REVISION" \
        --output-root "$APACHE_CASE_OUTPUT_ROOT" --output "$output"
    if [ -n "$actual_status" ]; then
        set -- "$@" --actual-status "$actual_status"
    fi
    "$@"
}

run_all_cases() {
    require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
    require_absolute_generated_path "$LOG_DIR" "$APACHE_LOG_DIR_LABEL"
    require_absolute_generated_path "$RESULTS_DIR" "RESULTS_DIR"
    require_absolute_generated_path "$RUNTIME_BASE" "RUNTIME_BASE"
    require_absolute_generated_path "$APACHE_CASE_OUTPUT_ROOT" "APACHE_CASE_OUTPUT_ROOT"

    prepare_runtime_directory "$LOG_DIR" "$APACHE_LOG_DIR_LABEL" 1
    prepare_runtime_directory "$RESULTS_DIR" "RESULTS_DIR" 0
    summary_file="$RESULTS_DIR/apache-summary.txt"
    json_file="$RESULTS_DIR/apache-summary.json"
    results_jsonl="$RESULTS_DIR/apache-results.jsonl"
    connector_summary="$RESULTS_DIR/connector-summary.txt"
    : > "$summary_file"
    : > "$results_jsonl"

    append_selected_phase4_fixtures
    cases=$(list_case_files) || exit 1
    if [ -z "$cases" ]; then
        echo "apache_smoke: fail no shared smoke cases found" >&2
        exit 1
    fi

    any_fail=0
    any_blocked=0
    any_not_executable=0
    index=0
    for case_path in $cases; do
        case_name=$(basename "$case_path" .yaml)
        case_log_dir="$LOG_DIR/$case_name"
        case_runtime="$RUNTIME_BASE/$case_name"
        case_port=$((BASE_PORT + index))
        echo "apache_smoke: running case=$case_name port=$case_port"
        set +e
        RUN_ONE_CASE=1 \
            TEST_CASE="$case_path" \
            LOG_DIR="$case_log_dir" \
            RUNTIME_ROOT="$case_runtime" \
            PORT="$case_port" \
            sh "$0"
        rc=$?
        set -e
        case_status=pass
        case_status_upper=PASS
        if [ "$rc" -eq 77 ]; then
            case_status=blocked
            case_status_upper=BLOCKED
            any_blocked=1
        elif [ "$rc" -eq 78 ]; then
            case_status=not_executable
            case_status_upper=NOT_EXECUTABLE
            any_not_executable=1
        elif [ "$rc" -ne 0 ]; then
            case_status=fail
            case_status_upper=FAIL
            any_fail=1
        fi
        actual_status=""
        if [ -f "$case_log_dir/observed-status.txt" ]; then
            actual_status=$(cat "$case_log_dir/observed-status.txt")
        fi
        observed_transport=$OBSERVED_TRANSPORT_HTTP_STATUS
        if [ -f "$case_log_dir/observed-transport-result.txt" ]; then
            observed_transport=$(cat "$case_log_dir/observed-transport-result.txt")
        fi
        reason=""
        if [ -f "$case_log_dir/status.txt" ]; then
            reason=$(tail -n 1 "$case_log_dir/status.txt")
        fi
        write_case_result "$case_path" "$case_status" "$actual_status" "$case_log_dir/result.json" "$observed_transport" "$reason" || \
            fail "Apache case result publication failed"
        [ -s "$case_log_dir/result.json" ] || { echo "apache_smoke: missing required result for $case_name" >&2; exit 1; }
        cat "$case_log_dir/result.json" >> "$results_jsonl"
        echo "$case_status_upper $case_name" | tee -a "$summary_file"
        index=$((index + 1))
    done

    set --
    for case_path in $cases; do
        set -- "$@" --expected-case "$(basename "$case_path" .yaml)"
    done
    "$PYTHON_BIN" "$CASE_CLI" summarize-results "$@" \
        --connector apache \
        --input-jsonl "$results_jsonl" \
        --summary-json "$json_file" \
        --summary-text "$summary_file" \
        --import-status-file "$TEST_ROOT/connector_suite/config/testing/import-status.json" \
        --connector-path real-world \
        --validation-mode real-world-connector-path \
        --server apache \
        --server-binary "$APACHE_HTTPD_BIN" \
        --module "$APACHE_MODULE" \
        --libmodsecurity "$MODSECURITY_LIB_DIR/libmodsecurity.so" \
        --origin-source "$CONNECTOR_ORIGIN_SOURCE" \
        --origin-source-repo "$CONNECTOR_ORIGIN_SOURCE_REPO" \
        --origin-source-url "$CONNECTOR_ORIGIN_SOURCE_URL" \
        --origin-source-commit "$CONNECTOR_ORIGIN_SOURCE_COMMIT" \
        --origin-source-version "$CONNECTOR_ORIGIN_SOURCE_VERSION" \
        --origin-license "$CONNECTOR_ORIGIN_LICENSE" \
        --origin-imported-path "$CONNECTOR_ORIGIN_IMPORTED_PATH" \
        --runtime-mode "$([ -n "${FORCE_ALL_CASES:-}" ] && printf force-all || printf default)" \
        --command "$([ -n "${FORCE_ALL_CASES:-}" ] && printf 'FORCE_ALL_CASES=1 make smoke-apache' || printf 'make smoke-apache')" \
        --exit-status "$([ "$any_fail" -ne 0 ] && printf 1 || { [ "$any_blocked" -ne 0 ] && printf 77 || printf 0; })" \
        --per-case-result-root "$LOG_DIR"
    cp "$summary_file" "$connector_summary"

    if [ "$any_fail" -ne 0 ]; then
        exit 1
    fi
    if [ "$any_blocked" -ne 0 ]; then
        exit 77
    fi
    exit 0
}

publish_profile_single_case_results() {
    [ "$RUN_ONE_CASE" = "1" ] || return 0
    apache_profile_enabled || return 0

    single_case_result="$LOG_DIR/result.json"
    "$PYTHON_BIN" -P "$APACHE_PROFILE_EVIDENCE_SCRIPT" publish-apache-selected-results \
        --runtime-root "$BUILD_ROOT" \
        --results-dir "$RESULTS_DIR" \
        --result-json "$single_case_result" \
        --case-cli "$CASE_CLI" \
        --import-status-file "$TEST_ROOT/connector_suite/config/testing/import-status.json" \
        --server-binary "$APACHE_HTTPD_BIN" \
        --module "$APACHE_MODULE" \
        --libmodsecurity "$MODSECURITY_LIB_DIR/libmodsecurity.so" \
        --origin-source "$CONNECTOR_ORIGIN_SOURCE" \
        --origin-source-repo "$CONNECTOR_ORIGIN_SOURCE_REPO" \
        --origin-source-url "$CONNECTOR_ORIGIN_SOURCE_URL" \
        --origin-source-commit "$CONNECTOR_ORIGIN_SOURCE_COMMIT" \
        --origin-source-version "$CONNECTOR_ORIGIN_SOURCE_VERSION" \
        --origin-license "$CONNECTOR_ORIGIN_LICENSE" \
        --origin-imported-path "$CONNECTOR_ORIGIN_IMPORTED_PATH" \
        --log-dir "$LOG_DIR" || \
        fail "selected Apache CRS summary publication failed"
}

find_apache() {
    if [ -n "$APACHE_HTTPD_BIN" ]; then
        printf '%s\n' "$APACHE_HTTPD_BIN"
    fi
}

find_apxs() {
    if [ -n "$APXS_BIN" ]; then
        printf '%s\n' "$APXS_BIN"
    fi
}

find_curl() {
    if [ -n "$CURL_BIN" ]; then
        printf '%s\n' "$CURL_BIN"
        return 0
    fi
    command -v curl 2>/dev/null || true
}

apache_modules_dir() {
    # APXS records its original staging prefix.  A managed Apache cache is
    # atomically published after the build, so use the final install prefix
    # first rather than trusting that historical path in apxs.
    if [ -d "$HTTPD_PREFIX/modules" ]; then
        printf '%s\n' "$HTTPD_PREFIX/modules"
        return 0
    fi
    if [ -n "$APXS_BIN" ] && [ -x "$APXS_BIN" ]; then
        dir=$("$APXS_BIN" -q LIBEXECDIR 2>/dev/null || true)
        if [ -n "$dir" ]; then
            printf '%s\n' "$dir"
            return 0
        fi
        libdir=$("$APXS_BIN" -q LIBDIR 2>/dev/null || true)
        if [ -n "$libdir" ]; then
            printf '%s/modules\n' "$libdir"
            return 0
        fi
    fi
    return 1
}

append_load_if_exists() {
    module_name=$1
    file_name=$2
    modules_dir=$3
    output=$4
    module_path="$modules_dir/$file_name"
    if [ -f "$module_path" ]; then
            {
                echo "<IfModule !$module_name>"
                echo "LoadModule $module_name \"$module_path\""
                echo "$IFMODULE_END"
            } >> "$output"
    fi
}

append_mpm_if_needed() {
    modules_dir=$1
    output=$2
    for candidate in \
        "mpm_event_module mod_mpm_event.so" \
        "mpm_worker_module mod_mpm_worker.so" \
        "mpm_prefork_module mod_mpm_prefork.so"
    do
        module_name=${candidate% *}
        file_name=${candidate#* }
        module_path="$modules_dir/$file_name"
        if [ -f "$module_path" ]; then
            {
                echo "<IfModule !mpm_event_module>"
                echo "<IfModule !mpm_worker_module>"
                echo "<IfModule !mpm_prefork_module>"
                echo "LoadModule $module_name \"$module_path\""
                echo "$IFMODULE_END"
                echo "$IFMODULE_END"
                echo "$IFMODULE_END"
            } >> "$output"
            return 0
        fi
    done
    return 0
}

escape_sed() {
    raw_value=$1
    printf '%s' "$raw_value" | sed 's/[&|]/\\&/g'
}

render_config() {
    case "${APACHE_PHASE4_MODE:-}" in
        off|safe|strict) ;;
        *) fail "unsupported resolved APACHE_PHASE4_MODE=${APACHE_PHASE4_MODE:-}" ;;
    esac
    sed \
        -e "s|@@RUNTIME_ROOT@@|$(escape_sed "$RUNTIME_ROOT")|g" \
        -e "s|@@LOG_DIR@@|$(escape_sed "$LOG_DIR")|g" \
        -e "s|@@PORT@@|$(escape_sed "$PORT")|g" \
        -e "s|@@MODULES_FILE@@|$(escape_sed "$MODULES_FILE")|g" \
        -e "s|@@APACHE_MODULE@@|$(escape_sed "$APACHE_MODULE")|g" \
        -e "s|@@DOCROOT@@|$(escape_sed "$DOCROOT")|g" \
        -e "s|@@APACHE_BACKEND_PROXY_FILE@@|$(escape_sed "$APACHE_BACKEND_PROXY_FILE")|g" \
        -e "s|@@RULES_FILE@@|$(escape_sed "$RULES_FILE")|g" \
        -e "s|@@APACHE_PHASE4_LOG@@|$(escape_sed "$APACHE_PHASE4_LOG_FILE")|g" \
        -e "s|@@APACHE_PHASE4_MODE@@|$(escape_sed "$APACHE_PHASE4_MODE")|g" \
        -e "s|@@APACHE_PHASE4_EXTRA_CONFIG@@|$(escape_sed "$APACHE_PHASE4_EXTRA_CONFIG")|g" \
        "$TEMPLATE" > "$CONFIG_FILE"
}

apache_profile_enabled() {
    if [ -z "$APACHE_PROFILE_CLEANUP_RECEIPT" ] && [ -z "$APACHE_PROFILE_CELL_RUN_ID" ] && \
        [ -z "$APACHE_PROFILE_GITHUB_RUN_ID" ] && [ -z "$APACHE_PROFILE_GITHUB_RUN_ATTEMPT" ]; then
        return 1
    fi
    [ -n "$APACHE_PROFILE_CLEANUP_RECEIPT" ] || return 2
    [ -n "$APACHE_PROFILE_CELL_RUN_ID" ] || return 2
    [ -n "$APACHE_PROFILE_GITHUB_RUN_ID" ] || return 2
    [ -n "$APACHE_PROFILE_GITHUB_RUN_ATTEMPT" ] || return 2
    return 0
}

require_safe_apache_config_path() {
    config_path=$1
    config_label=$2
    case "$config_path" in
        *[[:cntrl:]]*|*\"*|*[\\]*|*\$*)
            blocked "$config_label contains an unsafe Apache configuration character"
            ;;
        *) ;;
    esac
}

configure_apache_profile_audit() {
    if apache_profile_enabled; then
        :
    else
        profile_rc=$?
        case "$profile_rc" in
            1) return 0 ;;
            *) blocked "Apache profile audit configuration is incomplete" ;;
        esac
    fi
    [ "$MODSECURITY_TEST_VARIANT" = "with-crs" ] || \
        blocked "Apache profile audit evidence requires MODSECURITY_TEST_VARIANT=with-crs"
    [ "$RUN_ONE_CASE" = "1" ] || \
        blocked "Apache profile audit evidence requires one selected case"
    require_safe_apache_config_path "$AUDIT_LOG_FILE" "Apache profile audit path"
    [ ! -e "$AUDIT_LOG_FILE" ] || \
        fail "Apache profile audit log already exists before the selected case"
    {
        printf '%s\n' 'SecAuditEngine On'
        printf '%s\n' 'SecAuditLogType Serial'
        printf '%s\n' 'SecAuditLogFormat Native'
        printf '%s\n' 'SecAuditLogParts ABFHZ'
        printf 'SecAuditLog "%s"\n' "$AUDIT_LOG_FILE"
    } >> "$RULES_FILE" || fail "failed to append Apache profile audit configuration"
}

apache_profile_stop_tracked_process() {
    process_label=$1
    case "$process_label" in
        synchronized-upstream)
            process_pid=$2 SYNCHRONIZED_UPSTREAM_PID=
            ;;
        response-header-backend)
            process_pid=$2 RESPONSE_HEADER_BACKEND_PID=
            ;;
        *)
            process_pid=$2
            ;;
    esac
    [ -n "$process_pid" ] || return 0
    case "$process_pid" in
        *[!0-9]*|"") echo "apache_smoke: profile cleanup has invalid $process_label PID" >&2; return 1 ;;
        *) ;;
    esac
    if kill -0 "$process_pid" >/dev/null 2>&1; then
        kill "$process_pid" >/dev/null 2>&1 || true
        wait "$process_pid" >/dev/null 2>&1 || true
    fi
    if kill -0 "$process_pid" >/dev/null 2>&1; then
        echo "apache_smoke: profile cleanup left $process_label PID=$process_pid running" >&2
        return 1
    fi
    return 0
}

apache_profile_publish_cleanup_receipt() {
    [ "$APACHE_PROFILE_FINAL_CLEANUP" = "1" ] || return 0
    [ "$RUN_ONE_CASE" = "1" ] || return 1
    [ -n "${HTTPD_PID:-}" ] || {
        echo "apache_smoke: profile cleanup has no tracked Apache PID" >&2
        return 1
    }
    port_is_free "$PORT" || {
        echo "apache_smoke: profile cleanup left a listener on port=$PORT" >&2
        return 1
    }
    [ ! -e "$RUNTIME_PID_FILE" ] || {
        echo "apache_smoke: profile cleanup left Apache PID file=$RUNTIME_PID_FILE" >&2
        return 1
    }
    "$PYTHON_BIN" -P "$APACHE_PROFILE_EVIDENCE_SCRIPT" write-apache-cleanup-receipt \
        --output "$APACHE_PROFILE_CLEANUP_RECEIPT" \
        --cell-run-id "$APACHE_PROFILE_CELL_RUN_ID" \
        --github-run-id "$APACHE_PROFILE_GITHUB_RUN_ID" \
        --github-run-attempt "$APACHE_PROFILE_GITHUB_RUN_ATTEMPT" \
        --listener-port "$PORT"
}

cleanup() {
    cleanup_rc=0
    if [ -n "${SYNCHRONIZED_UPSTREAM_PID:-}" ] && \
        kill -0 "$SYNCHRONIZED_UPSTREAM_PID" >/dev/null 2>&1 && \
        [ -n "${SYNCHRONIZED_RELEASE_FILE:-}" ]; then
        : > "$SYNCHRONIZED_RELEASE_FILE" || cleanup_rc=77
    fi
    apache_profile_stop_tracked_process synchronized-upstream \
        "${SYNCHRONIZED_UPSTREAM_PID:-}" || cleanup_rc=77
    if [ "$HTTPD_RECORD_FAILURE_CLEANED" -eq 1 ]; then
        if [ -n "${HTTPD_SUPERVISOR_STATE:-}" ] && [ -f "$HTTPD_SUPERVISOR_STATE" ]; then
            "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" stop-supervisor \
                --state "$HTTPD_SUPERVISOR_STATE" >/dev/null 2>&1 || cleanup_rc=77
        fi
        if [ -n "${HTTPD_SUPERVISOR_PID:-}" ]; then
            wait_supervisor_bounded "$HTTPD_SUPERVISOR_PID" || cleanup_rc=77
        fi
        if ! port_is_free "$PORT"; then
            echo "apache_smoke: blocked Apache record-failure cleanup left port $PORT in use" >&2
            cleanup_rc=77
        fi
        if [ -e "${HTTPD_GUARD_EVIDENCE_CANDIDATE:-}" ] || \
            [ -L "${HTTPD_GUARD_EVIDENCE_CANDIDATE:-}" ]; then
            echo "apache_smoke: blocked Apache record-failure evidence rollback is incomplete" >&2
            cleanup_rc=77
        fi
    elif [ -n "${HTTPD_GUARD_EVIDENCE:-}" ] && [ -f "$HTTPD_GUARD_EVIDENCE" ]; then
        httpd_wait_safe=0
        if [ -n "${HTTPD_PID:-}" ] && kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
            if "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" verify-running \
                --evidence "$HTTPD_GUARD_EVIDENCE" >/dev/null 2>&1; then
                if "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" terminate \
                    --evidence "$HTTPD_GUARD_EVIDENCE" >/dev/null 2>&1; then
                    httpd_wait_safe=1
                else
                    cleanup_rc=77
                fi
            else
                cleanup_rc=77
            fi
        else
            httpd_wait_safe=1
        fi
        if [ -n "${HTTPD_PID:-}" ] && [ "$httpd_wait_safe" -eq 1 ]; then
            wait "$HTTPD_PID" >/dev/null 2>&1 || true
        fi
        if [ -n "${HTTPD_SUPERVISOR_PID:-}" ]; then
            wait_supervisor_bounded "$HTTPD_SUPERVISOR_PID" || cleanup_rc=77
        fi
        "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" verify-stopped \
            --evidence "$HTTPD_GUARD_EVIDENCE" >/dev/null 2>&1 || cleanup_rc=77
        if [ "$cleanup_rc" -eq 0 ] && [ -n "${RUNTIME_PID_FILE:-}" ]; then
            rm -f "$RUNTIME_PID_FILE"
            "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" verify-stopped \
                --evidence "$HTTPD_GUARD_EVIDENCE" --pidfile "$RUNTIME_PID_FILE" \
                >/dev/null 2>&1 || cleanup_rc=77
        fi
    elif [ -n "${HTTPD_PID:-}" ]; then
        echo "apache_smoke: blocked Apache ownership evidence is missing" >&2
        if [ -n "${HTTPD_SUPERVISOR_STATE:-}" ] && [ -f "$HTTPD_SUPERVISOR_STATE" ]; then
            "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" stop-supervisor \
                --state "$HTTPD_SUPERVISOR_STATE" >/dev/null 2>&1 || true
        fi
        if [ -n "${HTTPD_SUPERVISOR_PID:-}" ]; then
            wait_supervisor_bounded "$HTTPD_SUPERVISOR_PID" || cleanup_rc=77
        fi
        cleanup_rc=77
    fi
    apache_profile_stop_tracked_process response-header-backend \
        "${RESPONSE_HEADER_BACKEND_PID:-}" || cleanup_rc=77
    if [ -n "${PHASE4_ROGUE_TLS_KEY:-}" ] && ! rm -f "$PHASE4_ROGUE_TLS_KEY"; then
        cleanup_rc=77
    fi
    if [ "$cleanup_rc" -eq 0 ] && [ -n "${RUNTIME_PID_FILE:-}" ] && \
        [ ! -f "${HTTPD_GUARD_EVIDENCE:-}" ]; then
        rm -f "$RUNTIME_PID_FILE" || cleanup_rc=77
    fi
    if [ -n "${HTTPD_SUPERVISOR_STATE:-}" ] && [ -e "$HTTPD_SUPERVISOR_STATE" ]; then
        echo "apache_smoke: blocked supervisor state remains after cleanup" >&2
        cleanup_rc=77
    fi
    if [ -n "${HTTPD_SUPERVISOR_PID_OUTPUT:-}" ] && [ -e "$HTTPD_SUPERVISOR_PID_OUTPUT" ]; then
        echo "apache_smoke: blocked supervisor PID output remains after cleanup" >&2
        cleanup_rc=77
    fi
    if apache_profile_enabled && [ "$APACHE_PROFILE_FINAL_CLEANUP" = "1" ]; then
        [ "$cleanup_rc" -eq 0 ] || return "$cleanup_rc"
        apache_profile_publish_cleanup_receipt || return 1
    fi
    return "$cleanup_rc"
}

wait_supervisor_bounded() {
    supervisor_wait_pid=$1
    supervisor_wait_i=0
    while kill -0 "$supervisor_wait_pid" >/dev/null 2>&1 && [ "$supervisor_wait_i" -lt 40 ]; do
        supervisor_wait_i=$((supervisor_wait_i + 1))
        sleep 0.05
    done
    if kill -0 "$supervisor_wait_pid" >/dev/null 2>&1; then
        echo "apache_smoke: blocked Apache supervisor did not exit within bounded cleanup" >&2
        return 77
    fi
    wait "$supervisor_wait_pid" >/dev/null 2>&1 || true
}

on_exit() {
    exit_rc=$?
    trap - EXIT HUP INT TERM
    if cleanup; then
        cleanup_rc=0
    else
        cleanup_rc=$?
    fi
    if [ "$exit_rc" -eq 0 ] && [ "$cleanup_rc" -ne 0 ]; then
        exit_rc=$cleanup_rc
    fi
    exit "$exit_rc"
}

on_signal() {
    signal_rc=$1
    trap - EXIT HUP INT TERM
    cleanup || :
    exit "$signal_rc"
}

record_server_ownership() {
    HTTPD_GUARD_EVIDENCE_CANDIDATE="$RUNTIME_ROOT/run/httpd-ownership.json"
    if "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" record \
        --pid "$HTTPD_PID" --executable "$APACHE_HTTPD_BIN" \
        --port "$PORT" --output "$HTTPD_GUARD_EVIDENCE_CANDIDATE" >/dev/null; then
        HTTPD_GUARD_EVIDENCE="$HTTPD_GUARD_EVIDENCE_CANDIDATE"
        return 0
    else
        record_rc=$?
    fi
    HTTPD_GUARD_EVIDENCE=""
    if [ "$record_rc" -eq "$RECORD_FAILURE_CLEANED_EXIT" ]; then
        HTTPD_RECORD_FAILURE_CLEANED=1
    fi
    return "$record_rc"
}

port_is_free() {
    port_to_probe=$1
    "$PYTHON_BIN" - "$port_to_probe" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
}

port_accepts_tcp() {
    port_to_probe=$1
    "$PYTHON_BIN" - "$port_to_probe" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.2)
try:
    sock.connect(("127.0.0.1", port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
}

wait_tcp_port() {
    port_to_probe=$1
    i=0
    while [ "$i" -lt 30 ]; do
        if port_accepts_tcp "$port_to_probe"; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

select_free_port() {
    start_port=$1
    search_limit=$2
    offset=0
    while [ "$offset" -lt "$search_limit" ]; do
        candidate=$((start_port + offset))
        if port_is_free "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
        offset=$((offset + 1))
    done
    return 1
}

start_synchronized_upstream() {
    [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ] || return 0
    [ -f "$SYNCHRONIZED_UPSTREAM" ] || blocked "missing synchronized upstream helper: $SYNCHRONIZED_UPSTREAM"
    SYNCHRONIZED_DIR="$RUNTIME_ROOT/first-byte"
    SYNCHRONIZED_READY_FILE="$SYNCHRONIZED_DIR/upstream-ready.json"
    SYNCHRONIZED_PAUSED_FILE="$SYNCHRONIZED_DIR/upstream-paused.json"
    SYNCHRONIZED_RELEASE_FILE="$SYNCHRONIZED_DIR/upstream-release"
    SYNCHRONIZED_SERVER_EVIDENCE_FILE="$SYNCHRONIZED_DIR/upstream-server.json"
    rm -rf "$SYNCHRONIZED_DIR"
    prepare_runtime_directory "$SYNCHRONIZED_DIR" "Apache synchronized upstream" 1
    case "$APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT" in
        0|1) ;;
        *) fail "APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT must be 0 or 1" ;;
    esac
    if [ "$APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT" = "1" ]; then
        set -- "$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --serve \
            --control-root "$SYNCHRONIZED_DIR"
    else
        set -- "$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --serve
    fi
    "$@" \
        --ready-file "$SYNCHRONIZED_READY_FILE" \
        --paused-file "$SYNCHRONIZED_PAUSED_FILE" \
        --release-file "$SYNCHRONIZED_RELEASE_FILE" \
        --server-evidence-file "$SYNCHRONIZED_SERVER_EVIDENCE_FILE" \
        --timeout 30 >"$LOG_DIR/synchronized-upstream.stdout.log" \
        2>"$LOG_DIR/synchronized-upstream.stderr.log" &
    SYNCHRONIZED_UPSTREAM_PID=$!
    i=0
    while [ "$i" -lt 30 ]; do
        if [ -f "$SYNCHRONIZED_READY_FILE" ]; then
            break
        fi
        if ! kill -0 "$SYNCHRONIZED_UPSTREAM_PID" >/dev/null 2>&1; then
            blocked "synchronized upstream exited before publishing its address"
        fi
        i=$((i + 1))
        sleep 1
    done
    [ -f "$SYNCHRONIZED_READY_FILE" ] || blocked "synchronized upstream did not publish its address"
    RESPONSE_HEADER_BACKEND_PORT=$("$PYTHON_BIN" - "$SYNCHRONIZED_READY_FILE" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
port = payload.get("upstream_port")
if not isinstance(port, int) or port < 1 or port > 65535:
    raise SystemExit(1)
print(port)
PY
    ) || blocked "synchronized upstream ready record has no valid port"
}

send_synchronized_first_byte_request() {
    [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ] || return 1
    case "$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" in
        first_byte|bypass|precommit_deny|custom_mime_deny|allow|log_only|client_abort|engine_append_failure) ;;
        *) fail "unsupported MSCONNECTOR_PHASE4_SYNC_EXPECTATION=$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" ;;
    esac
    if [ "$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" = "first_byte" ]; then
        [ -n "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" ] || \
            fail "FULL_LIFECYCLE_EVIDENCE_OUTPUT is required for first_byte synchronization"
    fi
    request_url_path=$(quote_request_path "$REQUEST_PATH")
    : > "$RESPONSE_BODY"
    "$CURL_BIN" -sS --http1.1 --no-buffer -D "$RESPONSE_HEADERS" -X GET -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
        "http://127.0.0.1:$PORT$request_url_path" >"$LOG_DIR/first-byte-status.txt" \
        2>"$LOG_DIR/first-byte-client.err" &
    FIRST_BYTE_CLIENT_PID=$!
    observed_first_byte=0
    upstream_paused=0
    i=0
    while [ "$i" -lt 300 ]; do
        if [ -f "$SYNCHRONIZED_PAUSED_FILE" ]; then
            upstream_paused=1
            if [ -s "$RESPONSE_BODY" ]; then
                observed_first_byte=1
            fi
            case "$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" in
                first_byte|bypass)
                    [ "$observed_first_byte" -eq 1 ] && break
                    ;;
                precommit_deny|custom_mime_deny|allow|log_only|client_abort|engine_append_failure)
                    # Keep a bounded observation window after the upstream has
                    # confirmed that its first chunk is sent but EOS is absent.
                    # A P4 gate must not release original body bytes here.
                    [ "$i" -ge 10 ] && break
                    ;;
                *) fail "unsupported MSCONNECTOR_PHASE4_SYNC_EXPECTATION=$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" ;;
            esac
        fi
        if ! kill -0 "$FIRST_BYTE_CLIENT_PID" >/dev/null 2>&1; then
            break
        fi
        i=$((i + 1))
        sleep 0.1
    done
    if [ "$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" = "client_abort" ]; then
        [ "$upstream_paused" -eq 1 ] || \
            fail "client-abort test did not reach the paused-before-EOS barrier"
        [ "$observed_first_byte" -eq 0 ] || \
            fail "client-abort test released an in-scope response byte before EOS"
        if ! kill -0 "$FIRST_BYTE_CLIENT_PID" >/dev/null 2>&1; then
            fail "client-abort test client exited before the upstream barrier"
        fi
        kill "$FIRST_BYTE_CLIENT_PID" >/dev/null 2>&1 || \
            fail "client-abort test could not stop its task-owned client"
        set +e
        wait "$FIRST_BYTE_CLIENT_PID"
        client_rc=$?
        set -e
        : > "$SYNCHRONIZED_RELEASE_FILE"
        set +e
        wait "$SYNCHRONIZED_UPSTREAM_PID"
        upstream_rc=$?
        SYNCHRONIZED_UPSTREAM_PID=
        set -e
    else
        : > "$SYNCHRONIZED_RELEASE_FILE"
        set +e
        wait "$FIRST_BYTE_CLIENT_PID"
        client_rc=$?
        set -e
        upstream_rc=0
    fi
    [ "$upstream_paused" -eq 1 ] || \
        fail "synchronized upstream did not publish its paused-before-EOS barrier"
    http_status=$(cat "$LOG_DIR/first-byte-status.txt" 2>/dev/null || true)
    case "$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" in
        first_byte)
            [ "$observed_first_byte" -eq 1 ] || \
                fail "client did not receive a first response byte while upstream was paused"
            [ "$client_rc" -eq 0 ] || \
                fail "synchronized client failed after upstream release rc=$client_rc"
            [ "$http_status" = "200" ] || \
                fail "synchronized safe response status was not 200: $http_status"
            [ -s "$APACHE_PHASE4_LOG_FILE" ] || \
                fail "Phase-4 host log is missing after synchronized response"
            FIRST_BYTE_HOST_METADATA="$SYNCHRONIZED_DIR/host-metadata.json"
            "$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-first-byte-host-metadata.py" \
                --phase4-log "$APACHE_PHASE4_LOG_FILE" --output "$FIRST_BYTE_HOST_METADATA" || \
                fail "could not derive bounded host metadata from the Phase-4 event"
            "$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --merge-evidence \
                --paused-file "$SYNCHRONIZED_PAUSED_FILE" \
                --client-first-byte-file "$RESPONSE_BODY" \
                --host-metadata-json "$FIRST_BYTE_HOST_METADATA" \
                --evidence-origin real_host \
                --output "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" || \
                fail "could not write synchronized first-byte evidence"
            ;;
        bypass)
            [ "$observed_first_byte" -eq 1 ] || \
                fail "bypass reproduction did not expose a body byte before EOS"
            [ "$client_rc" -eq 0 ] || \
                fail "bypass reproduction client failed after release rc=$client_rc"
            [ "$http_status" = "200" ] || \
                fail "bypass reproduction expected status 200, observed $http_status"
            grep -F "$PHASE4_FIRST_BYTE_PREFIX" "$RESPONSE_BODY" >/dev/null 2>&1 || \
                fail "bypass reproduction body omitted the pre-EOS prefix"
            grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1 || \
                fail "bypass reproduction body omitted the Phase-4 marker"
            [ -s "$APACHE_PHASE4_LOG_FILE" ] || \
                fail "bypass reproduction Phase-4 intervention log is missing"
            grep -F '"rule_id":"2190401"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "bypass reproduction did not record Phase-4 rule 2190401"
            grep -F '"actual_action":"log_only"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "bypass reproduction did not take the Safe log_only fallback"
            grep -F '"reason":"response_committed_safe"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "bypass reproduction did not record a committed response"
            require_audit_rule 2190401 \
                "bypass reproduction audit log lacks rule 2190401"
            ;;
        precommit_deny)
            [ "$observed_first_byte" -eq 0 ] || \
                fail "pre-commit deny released original response bytes before EOS"
            [ "$client_rc" -eq 0 ] || \
                fail "pre-commit deny client failed after release rc=$client_rc"
            [ "$http_status" = "403" ] || \
                fail "pre-commit deny expected status 403, observed $http_status"
            assert_single_h1_status 403
            if grep -F "$PHASE4_FIRST_BYTE_PREFIX" "$RESPONSE_BODY" >/dev/null 2>&1 || \
                grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1; then
                fail "pre-commit deny leaked original response bytes"
            fi
            [ -s "$APACHE_PHASE4_LOG_FILE" ] || \
                fail "pre-commit deny Phase-4 intervention log is missing"
            grep -F '"rule_id":"2190401"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "pre-commit deny did not record Phase-4 rule 2190401"
            grep -F '"actual_action":"deny"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "pre-commit deny did not retain the disruptive action"
            grep -F '"reason":"response_not_committed"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "pre-commit deny did not record the uncommitted boundary"
            grep -F '"response_committed":false' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "pre-commit deny recorded an already-committed response"
            grep -F '"eos_seen":true' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "pre-commit deny did not record the EOS decision boundary"
            require_audit_rule 2190401 \
                "pre-commit deny audit log lacks rule 2190401"
            ;;
        custom_mime_deny)
            [ "$observed_first_byte" -eq 0 ] || \
                fail "custom-MIME pre-commit deny released original response bytes before EOS"
            [ "$client_rc" -eq 0 ] || \
                fail "custom-MIME pre-commit deny client failed after release rc=$client_rc"
            [ "$http_status" = "403" ] || \
                fail "custom-MIME pre-commit deny expected status 403, observed $http_status"
            assert_single_h1_status 403
            if grep -F "$PHASE4_FIRST_BYTE_PREFIX" "$RESPONSE_BODY" >/dev/null 2>&1 || \
                grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1; then
                fail "custom-MIME pre-commit deny leaked original response bytes"
            fi
            [ -s "$APACHE_PHASE4_LOG_FILE" ] || \
                fail "custom-MIME pre-commit deny Phase-4 intervention log is missing"
            grep -F '"rule_id":"2190404"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "custom-MIME pre-commit deny did not record Phase-4 rule 2190404"
            grep -F '"actual_action":"deny"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "custom-MIME pre-commit deny did not retain the disruptive action"
            grep -F '"reason":"response_not_committed"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "custom-MIME pre-commit deny did not record the uncommitted boundary"
            grep -F '"response_committed":false' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
                fail "custom-MIME pre-commit deny recorded an already-committed response"
            require_audit_rule 2190404 \
                "custom-MIME pre-commit deny audit log lacks rule 2190404"
            ;;
        engine_append_failure)
            [ "$client_rc" -eq 0 ] || \
                fail "engine ProcessPartial failure client failed rc=$client_rc"
            [ "$http_status" = "500" ] || \
                fail "engine ProcessPartial failure expected status 500, observed $http_status"
            assert_single_h1_status 500
            if grep -F "$PHASE4_FIRST_BYTE_PREFIX" "$RESPONSE_BODY" >/dev/null 2>&1 || \
                grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1; then
                fail "engine ProcessPartial failure released an uninspected original response byte"
            fi
            grep -F 'failed to append response body to libmodsecurity' "$LOG_DIR/error.log" >/dev/null 2>&1 || \
                fail "engine ProcessPartial failure did not take the connector fail-closed path"
            ;;
        allow)
            [ "$observed_first_byte" -eq 0 ] || \
                fail "in-scope allow released bytes before its Phase-4 EOS boundary"
            [ "$client_rc" -eq 0 ] || \
                fail "in-scope allow client failed after release rc=$client_rc"
            [ "$http_status" = "200" ] || \
                fail "in-scope allow expected status 200, observed $http_status"
            assert_text_response_headers 200 44
            expected_body="first-byte-prefix$PHASE4_RESPONSE_BODY_MARKER"
            actual_body=$(cat "$RESPONSE_BODY")
            [ "$actual_body" = "$expected_body" ] || \
                fail "in-scope allow body was lost, reordered, or emitted more than once"
            [ ! -s "$APACHE_PHASE4_LOG_FILE" ] || \
                fail "in-scope allow unexpectedly emitted a disruptive Phase-4 event"
            ;;
        log_only)
            [ "$observed_first_byte" -eq 0 ] || \
                fail "Phase-4 log-only control released bytes before EOS"
            [ "$client_rc" -eq 0 ] || \
                fail "Phase-4 log-only client failed after release rc=$client_rc"
            [ "$http_status" = "200" ] || \
                fail "Phase-4 log-only expected status 200, observed $http_status"
            assert_text_response_headers 200 44
            expected_body="first-byte-prefix$PHASE4_RESPONSE_BODY_MARKER"
            actual_body=$(cat "$RESPONSE_BODY")
            [ "$actual_body" = "$expected_body" ] || \
                fail "Phase-4 log-only body was lost, reordered, or emitted more than once"
            require_audit_rule 2190402 \
                "Phase-4 log-only audit log lacks rule 2190402"
            [ ! -s "$APACHE_PHASE4_LOG_FILE" ] || \
                fail "Phase-4 log-only unexpectedly emitted a disruptive intervention event"
            ;;
        client_abort)
            [ "$client_rc" -ne 0 ] || \
                fail "client-abort test client unexpectedly completed normally"
            [ "$upstream_rc" -eq 0 ] || \
                fail "client-abort test upstream did not complete after release rc=$upstream_rc"
            [ ! -s "$RESPONSE_BODY" ] || \
                fail "client-abort test retained a protected response byte after client disconnect"
            [ -s "$SYNCHRONIZED_SERVER_EVIDENCE_FILE" ] || \
                fail "client-abort test upstream did not publish terminal evidence"
            "$PYTHON_BIN" - "$SYNCHRONIZED_SERVER_EVIDENCE_FILE" <<'PY' || \
                fail "client-abort test upstream terminal evidence is invalid"
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload.get("upstream_eos_sent") is not True:
    raise SystemExit(1)
if payload.get("body_payload_persisted") is not False:
    raise SystemExit(1)
PY
            if ! kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
                fail "client-abort test caused the Apache host to exit"
            fi
            ;;
        *) fail "unsupported MSCONNECTOR_PHASE4_SYNC_EXPECTATION=$MSCONNECTOR_PHASE4_SYNC_EXPECTATION" ;;
    esac
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
    return 0
}

stop_stale_runtime_pid() {
    pid_file=$1
    [ -f "$pid_file" ] || return 0
    case "$pid_file" in
        "$BUILD_ROOT"/*) ;;
        *) blocked "runtime pid file is outside BUILD_ROOT: $pid_file" ;;
    esac
    stale_pid=$(cat "$pid_file" 2>/dev/null || true)
    case "$stale_pid" in
        ""|*[!0-9]*)
            [ ! -f "$RUNTIME_ROOT/run/httpd-ownership.json" ] || \
                blocked "runtime pid file is invalid while Apache ownership evidence exists"
            rm -f "$pid_file"
            return 0
            ;;
        *) ;;
    esac
    stale_guard="$RUNTIME_ROOT/run/httpd-ownership.json"
    [ -f "$stale_guard" ] || blocked "runtime pid file has no verified Apache ownership evidence"
    "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" verify-pid \
        --evidence "$stale_guard" --pid "$stale_pid" >/dev/null || \
        blocked "runtime pid file PID does not match verified Apache evidence"
    echo "apache_smoke: stopping stale verified runtime process pid=$stale_pid"
    if ! "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" terminate \
        --evidence "$stale_guard" >/dev/null; then
        "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" verify-stopped \
            --evidence "$stale_guard" >/dev/null || \
            blocked "stale runtime process identity or listener ownership changed"
    fi
    rm -f "$pid_file"
    "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" verify-stopped \
        --evidence "$stale_guard" --pidfile "$pid_file" >/dev/null || \
        blocked "stale Apache listener cleanup could not be proven"
}

retire_stale_guard_evidence() {
    stale_guard="$RUNTIME_ROOT/run/httpd-ownership.json"
    [ -f "$stale_guard" ] || return 0
    "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" verify-stopped \
        --evidence "$stale_guard" >/dev/null || \
        blocked "stale Apache ownership evidence cannot be retired safely"
    rm -f "$stale_guard"
}

bind_conflict_seen() {
    grep -E "Address already in use|could not bind|make_sock.*could not bind" \
        "$LOG_DIR/httpd.log" \
        "$LOG_DIR/error.log" \
        "$RUNTIME_ROOT/logs/error.log" >/dev/null 2>&1
}

start_server() {
    attempt=0
    while :; do
        selected_port=$(select_free_port "$PORT" "$PORT_SEARCH_LIMIT") || \
            blocked "no free localhost port found from $PORT within $PORT_SEARCH_LIMIT attempts"
        if [ "$selected_port" != "$PORT" ]; then
            echo "apache_smoke: selected free port=$selected_port after requested port=$PORT was unavailable"
            echo "info: selected port $selected_port after requested port $PORT was unavailable" >> "$STATUS_FILE"
        fi
        PORT="$selected_port"
        render_config

        if ! "$APACHE_HTTPD_BIN" -t -f "$CONFIG_FILE" > "$LOG_DIR/configtest.log" 2>&1; then
            if configtest_case_not_executable; then
                not_executable "Apache rejected generated ModSecurity rules; see $LOG_DIR/configtest.log"
            fi
            fail "Apache configtest failed; see $LOG_DIR/configtest.log"
        fi

        if [ "$MSCONNECTOR_SMOKE_STAGE" = "config_load" ]; then
            return 0
        fi

        HTTPD_SUPERVISOR_STATE="$RUNTIME_ROOT/run/httpd-supervisor-state.json"
        HTTPD_SUPERVISOR_PID_OUTPUT="$RUNTIME_ROOT/run/httpd-supervisor.pid"
        MSCONNECTOR_APACHE_GUARD_HTTPD="$APACHE_HTTPD_BIN" \
            "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" supervise \
            --state "$HTTPD_SUPERVISOR_STATE" \
            --pid-output "$HTTPD_SUPERVISOR_PID_OUTPUT" \
            > /dev/null 2> "$LOG_DIR/httpd.log" &
        HTTPD_SUPERVISOR_PID=$!
        i=0
        while [ "$i" -lt 20 ] && [ ! -s "$HTTPD_SUPERVISOR_PID_OUTPUT" ]; do
            if ! kill -0 "$HTTPD_SUPERVISOR_PID" >/dev/null 2>&1; then
                fail "Apache supervisor exited during launch; see $LOG_DIR/httpd.log"
            fi
            i=$((i + 1))
            sleep 0.05
        done
        [ -s "$HTTPD_SUPERVISOR_PID_OUTPUT" ] || fail "Apache supervisor did not publish child PID"
        HTTPD_PID=$(sed -n '1p' "$HTTPD_SUPERVISOR_PID_OUTPUT")
        case "$HTTPD_PID" in
            ''|*[!0-9]*) fail "Apache supervisor published an invalid child PID" ;;
            *) : ;;
        esac

        if [ "$MSCONNECTOR_SMOKE_STAGE" = "start_smoke" ]; then
            sleep 1
            if kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
                record_server_ownership || \
                    blocked "Apache listener ownership could not be proven"
                return 0
            fi
            fail "Apache exited during request-free start smoke; see $LOG_DIR/httpd.log"
        fi

        ready=0
        i=0
        while [ "$i" -lt 30 ]; do
            if ! kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
                if [ "$attempt" -lt "$PORT_RETRY_LIMIT" ] && bind_conflict_seen; then
                    cleanup
                    attempt=$((attempt + 1))
                    PORT=$((PORT + 1))
                    echo "apache_smoke: retrying after bind conflict attempt=$attempt"
                    echo "info: retrying after bind conflict attempt=$attempt" >> "$STATUS_FILE"
                    continue 2
                fi
                fail "Apache exited before request; see $LOG_DIR/httpd.log"
            fi
            if [ "${ON_DEMAND_TESTS:-0}" != 1 ]; then
                # Automatic startup opens transport only. The inventoried
                # request supplies HTTP/WAF behavior and its own assertions.
                if port_accepts_tcp "$PORT" >/dev/null 2>"$LOG_DIR/curl-ready.err"; then
                    ready=1
                    break
                fi
            else
                if phase4_terminal_test_uses_h2; then
                    ready_url="https://127.0.0.1:$PORT/__modsec_smoke_ready"
                    set -- "$CURL_BIN" -sS -k --http1.1 -o /dev/null "$ready_url"
                else
                    ready_url="http://127.0.0.1:$PORT/__modsec_smoke_ready"
                    set -- "$CURL_BIN" -sS -o /dev/null "$ready_url"
                fi
                if "$@" >/dev/null 2>"$LOG_DIR/curl-ready.err"; then
                    ready=1
                    break
                fi
            fi
            i=$((i + 1))
            sleep 1
        done

        if [ "$ready" -eq 1 ]; then
            record_server_ownership || \
                blocked "Apache listener ownership could not be proven"
            return 0
        fi
        fail "Apache did not become ready on 127.0.0.1:$PORT"
    done
}

send_case_request() {
    set -- "$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" -X "$REQUEST_METHOD" -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT"
    if [ -n "${REQUEST_HEADERS_FILE:-}" ] && [ -s "$REQUEST_HEADERS_FILE" ]; then
        while IFS= read -r header_line || [ -n "$header_line" ]; do
            [ -n "$header_line" ] || continue
            case "$header_line" in
                *:*)
                    header_value=${header_line#*:}
                    case "$header_value" in
                        ''|' ') header_line="${header_line%%:*};" ;;
                        *) : ;;
                    esac
                    ;;
                *) : ;;
            esac
            set -- "$@" -H "$header_line"
        done < "$REQUEST_HEADERS_FILE"
    fi
    if [ "${REQUEST_HAS_BODY:-0}" = "1" ]; then
        set -- "$@" --data-binary "@$REQUEST_BODY_FILE"
    fi
    request_url_path=$(quote_request_path "$REQUEST_PATH")
    set -- "$@" "http://127.0.0.1:$PORT$request_url_path"
    "$PYTHON_BIN" "$CASE_CLI" request-window --phase begin \
        --case "$TEST_CASE" --event-log "$LOG_DIR/phase4.log" \
        --receipt "$LOG_DIR/request-window.json" --output-root "$APACHE_CASE_OUTPUT_ROOT" \
        --run-id "$RESULT_RUN_ID" --source-revision "$CONNECTOR_REVISION" || return 1
    request_status=0
    "$@" 2>"$LOG_DIR/curl-attack.err" || request_status=$?
    "$PYTHON_BIN" "$CASE_CLI" request-window --phase end \
        --case "$TEST_CASE" --event-log "$LOG_DIR/phase4.log" \
        --receipt "$LOG_DIR/request-window.json" --output-root "$APACHE_CASE_OUTPUT_ROOT" \
        --run-id "$RESULT_RUN_ID" --source-revision "$CONNECTOR_REVISION" || return 1
    return "$request_status"
}

assert_single_h1_status() {
    expected_status=$1
    [ -s "$RESPONSE_HEADERS" ] || \
        fail "response headers are missing for expected HTTP/1 status $expected_status"
    status_count=$(grep -Ec "^HTTP/1\\.[01] $expected_status " "$RESPONSE_HEADERS" || true)
    [ "$status_count" -eq 1 ] || \
        fail "expected exactly one HTTP/1 $expected_status status line, observed $status_count"
    total_status_count=$(grep -Ec '^HTTP/1\.[01] [0-9][0-9][0-9] ' "$RESPONSE_HEADERS" || true)
    [ "$total_status_count" -eq 1 ] || \
        fail "expected exactly one total HTTP/1 response status line, observed $total_status_count"
}

assert_single_h2_status() {
    expected_status=$1
    [ -s "$RESPONSE_HEADERS" ] || \
        fail "response headers are missing for expected HTTP/2 status $expected_status"
    status_count=$(grep -Ec "^HTTP/2 $expected_status([[:space:]]|$)" "$RESPONSE_HEADERS" || true)
    [ "$status_count" -eq 1 ] || \
        fail "expected exactly one HTTP/2 $expected_status status line, observed $status_count"
    total_status_count=$(grep -Ec '^HTTP/2 [0-9][0-9][0-9]([[:space:]]|$)' "$RESPONSE_HEADERS" || true)
    [ "$total_status_count" -eq 1 ] || \
        fail "expected exactly one total HTTP/2 response status line, observed $total_status_count"
}

assert_text_response_headers() {
    expected_status=$1
    expected_bytes=$2
    body_bytes=$(wc -c < "$RESPONSE_BODY")

    assert_single_h1_status "$expected_status"
    grep -Eqi '^Content-Type:[[:space:]]*text/plain([;[:space:]]|$)' "$RESPONSE_HEADERS" || \
        fail "expected text/plain response content type"
    [ "$body_bytes" -eq "$expected_bytes" ] || \
        fail "response body length $body_bytes does not match expected $expected_bytes"
    content_length=$(awk '/^[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]:/ { gsub(/\r/, "", $2); print $2; exit }' "$RESPONSE_HEADERS")
    if [ -n "$content_length" ]; then
        [ "$content_length" -eq "$body_bytes" ] || \
            fail "Content-Length $content_length does not match response body length $body_bytes"
    fi
}

assert_phase4_rogue_no_leak() {
    body_file=$1
    for forbidden in \
        phase4-rogue-prefix- \
        "$PHASE4_RESPONSE_BODY_MARKER" \
        phase4-rogue-suffix-after-eos \
        phase4-rogue-late-after-deny
    do
        if grep -F "$forbidden" "$body_file" >/dev/null 2>&1; then
            fail "Phase-4 rogue terminal test leaked protected marker: $forbidden"
        fi
    done
}

assert_phase4_rogue_error_document() {
    body_file=$1
    expected_file="$LOG_DIR/phase4-rogue-error-document.expected"

    printf '%s\n' 'phase4-custom-deny-body' > "$expected_file"
    cmp -s "$expected_file" "$body_file" || \
        fail "local ErrorDocument body was not the sole terminal Phase-4 response"
    assert_phase4_error_document_headers "$expected_file" 403
}


assert_phase4_error_document_headers() {
    expected_file=$1
    expected_status=$2
    expected_bytes=$(wc -c < "$expected_file")

    if [ "$APACHE_PHASE4_ROGUE_PROTOCOL" = "http1" ]; then
        assert_text_response_headers "$expected_status" "$expected_bytes"
    fi
    if [ -s "$RESPONSE_HEADERS" ] && \
        grep -Eqi '^X-Phase4-Original-Response:' "$RESPONSE_HEADERS"; then
        fail "local ErrorDocument retained an original response header"
    fi
}

assert_phase4_rogue_allow_body() {
    body_file=$1
    expected_file="$LOG_DIR/phase4-rogue-allow.expected"

    printf '%s%s' 'phase4-rogue-prefix-' "$PHASE4_RESPONSE_BODY_MARKER" > "$expected_file"
    cmp -s "$expected_file" "$body_file" || \
        fail "Phase-4 rogue allow response lost, duplicated, or retained an invalid suffix"
    for forbidden in phase4-rogue-suffix-after-eos phase4-rogue-late-after-deny
    do
        if grep -F "$forbidden" "$body_file" >/dev/null 2>&1; then
            fail "Phase-4 rogue allow response leaked invalid marker: $forbidden"
        fi
    done
}

assert_phase3_header_freeze_headers() {
    headers_file=$1

    grep -F 'header_mutation=1' "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-3 header-freeze rogue producer did not mutate the header after P3"
    if grep -Eqi '^X-Phase3-Late:' "$headers_file"; then
        fail "Phase-3 header-freeze response emitted a header not inspected by Phase 3"
    fi
    grep -Eqi '^ETag:[[:space:]]*"phase3-inspected-etag"' "$headers_file" || \
        fail "Phase-3 header-freeze response lost the P3-inspected ETag through a late no-etag note"
}

assert_phase4_rogue_producer_trace() {
    case "$APACHE_PHASE4_ROGUE_PHASE:$APACHE_PHASE4_ROGUE_EXPECT" in
        p4:deny)
            expected_trace='first_rc=0 deny_rc=-?[1-9][0-9]* late_rc=-?[1-9][0-9]*'
            ;;
        p4:allow)
            expected_trace='first_rc=0 deny_rc=0 late_rc=-?[1-9][0-9]*'
            ;;
        p3:deny)
            expected_trace='first_rc=-?[1-9][0-9]* deny_rc=-?[1-9][0-9]* late_rc=-?[1-9][0-9]*'
            ;;
        p3:allow)
            expected_trace='first_rc=0 deny_rc=0 late_rc=-?[1-9][0-9]*'
            ;;
        *) fail "unsupported Phase-4 rogue phase/expectation combination: $APACHE_PHASE4_ROGUE_PHASE/$APACHE_PHASE4_ROGUE_EXPECT" ;;
    esac
    grep -E "$expected_trace" "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 rogue producer did not follow the required first/EOS/late sequence"
}

assert_phase4_rogue_evidence() {
    case "$APACHE_PHASE4_ROGUE_EXPECT" in
        deny)
            case "$APACHE_PHASE4_ROGUE_PHASE" in
                p4)
                    rogue_rule_id=2190401
                    rogue_reason=response_not_committed
                    ;;
                p3)
                    rogue_rule_id=2190406
                    rogue_reason=response_headers_before_commit
                    ;;
                *) fail "unsupported APACHE_PHASE4_ROGUE_PHASE=$APACHE_PHASE4_ROGUE_PHASE" ;;
            esac
            [ -s "$APACHE_PHASE4_LOG_FILE" ] || \
                fail "Phase-4 rogue terminal test intervention log is missing"
            "$PYTHON_BIN" - "$APACHE_PHASE4_LOG_FILE" "$rogue_rule_id" "$rogue_reason" <<'PY'
import json
import sys

rule_id = sys.argv[2]
reason = sys.argv[3]
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if (str(event.get("rule_id")) == rule_id
            and event.get("actual_action") == "deny"
            and event.get("reason") == reason
            and event.get("response_committed") is False):
        sys.exit(0)
raise SystemExit(
    "Phase-4 rogue terminal test lacks one matching pre-commit deny event")
PY
            require_audit_rule "$rogue_rule_id" \
                "Phase-4 rogue terminal test audit log lacks the matching rule"
            ;;
        allow) ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_EXPECT=$APACHE_PHASE4_ROGUE_EXPECT" ;;
    esac
    if [ "$APACHE_PHASE4_ROGUE_PHASE:$APACHE_PHASE4_ROGUE_EXPECT" = "p3:deny" ] && \
        ! grep -F 'ModSecurity Phase4 rogue test issued late response brigade' \
            "$LOG_DIR/error.log" >/dev/null 2>&1; then
        # ap_die() can synchronously finish Apache's header-stage denial and
        # not return to the handler at all. The observed 403 plus the native
        # P3 event/audit above is stronger than a synthetic late write in that
        # path; P4 deny still requires the explicit late-producer attempt.
        return 0
    fi
    grep -F 'ModSecurity Phase4 rogue test issued late response brigade' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 rogue handler did not attempt the required late brigade"
    if grep -F 'late_rc=0' "$LOG_DIR/error.log" >/dev/null 2>&1; then
        fail "Phase-4 terminal guard accepted the required late brigade"
    fi
    assert_phase4_rogue_producer_trace
}

phase4_redirect_direct_rule_event_count() {
    direct_rule_id=$1
    if [ ! -s "$APACHE_PHASE4_LOG_FILE" ]; then
        printf '%s\n' 0
        return 0
    fi
    "$PYTHON_BIN" - "$APACHE_PHASE4_LOG_FILE" "$direct_rule_id" <<'PY'
import json
import sys

count = 0
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if (str(event.get("rule_id")) == sys.argv[2]
            and event.get("actual_action") == "deny"
            and event.get("reason") == "response_not_committed"
            and event.get("response_committed") is False):
        count += 1
print(count)
PY
}

assert_phase4_redirect_direct_control() {
    direct_headers="$LOG_DIR/phase4-redirect-target-direct.headers"
    direct_body="$LOG_DIR/phase4-redirect-target-direct.body"

    [ "$APACHE_PHASE4_ROGUE_PROTOCOL" = "http1" ] || \
        fail "Phase-4 internal redirect direct control currently requires H1"
    : > "$direct_body"
    set +e
    direct_status=$("$CURL_BIN" -sS --http1.1 -D "$direct_headers" \
        -o "$direct_body" -w "$CURL_HTTP_STATUS_FORMAT" \
        "http://127.0.0.1:$PORT/__phase4_internal_redirect_target.txt")
    direct_curl_rc=$?
    set -e
    [ "$direct_curl_rc" -eq 0 ] || \
        fail "Phase-4 internal redirect direct control client failed rc=$direct_curl_rc"
    [ "$direct_status" = "403" ] || \
        fail "Phase-4 internal redirect direct control expected 403, observed $direct_status"
    status_count=$(grep -Ec '^HTTP/1\.[01] 403 ' "$direct_headers" || true)
    [ "$status_count" -eq 1 ] || \
        fail "Phase-4 internal redirect direct control did not return exactly one H1 403"
    if grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$direct_body" >/dev/null 2>&1; then
        fail "Phase-4 internal redirect direct control leaked the marker body"
    fi
    redirect_direct_rule_events_before=$(phase4_redirect_direct_rule_event_count \
        "$APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID")
    [ "$redirect_direct_rule_events_before" -ge 1 ] || \
        fail "Phase-4 internal redirect direct control lacks rule $APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID evidence"
    require_audit_rule "$APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID" \
        "Phase-4 internal redirect direct control lacks audit rule $APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID"
}

assert_phase4_internal_redirect_target_handler_was_not_run() {
    [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" = "1" ] || return 0
    if grep -F 'ModSecurity Phase4 redirect target handler executed' \
        "$LOG_DIR/error.log" >/dev/null 2>&1; then
        fail "Phase-4 normal redirect invoked the target handler before fail-closed refusal"
    fi
}

send_phase4_internal_redirect_request() {
    redirect_expected="$LOG_DIR/phase4-internal-redirect.expected"
    redirect_request_uri=/__phase4_internal_redirect

    printf '%s' "$PHASE4_RESPONSE_BODY_MARKER" > "$redirect_expected"
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" = "1" ]; then
        redirect_request_uri=/__phase4_internal_redirect_target_handler_test
    fi
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ] || \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST" = "1" ]; then
        assert_phase4_redirect_direct_control
    fi
    case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
        http1)
            : > "$RESPONSE_BODY"
            set +e
            http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
                -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
                "http://127.0.0.1:$PORT$redirect_request_uri")
            curl_rc=$?
            set -e
            case "$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" in
                abort|target_config_abort|uri_policy_abort|target_handler_abort) ;;
                *)
                    [ "$curl_rc" -eq 0 ] || \
                        fail "Phase-4 internal redirect H1 client failed rc=$curl_rc"
                    ;;
            esac
            ;;
        h2)
            "$CURL_BIN" --version | grep -E "$CURL_HTTP2_FEATURE_PATTERN" >/dev/null 2>&1 || \
                blocked "curl lacks HTTP/2 support required for the Phase-4 internal redirect H2 test"
            : > "$RESPONSE_BODY"
            : > "$RESPONSE_HEADERS"
            set +e
            "$CURL_BIN" -sS -k --http2 --trace-ids \
                --trace-ascii "$PHASE4_ROGUE_TRACE" \
                -D "$RESPONSE_HEADERS" -o "$RESPONSE_BODY" \
                -w "$CURL_HTTP_STATUS_VERSION_FORMAT" \
                "https://127.0.0.1:$PORT$redirect_request_uri" \
                > "$PHASE4_ROGUE_TRANSFERS" \
                2> "$LOG_DIR/phase4-internal-redirect-h2-client.err"
            curl_rc=$?
            set -e
            http_status=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_STATUS" \
                "$PHASE4_ROGUE_TRANSFERS")
            http_version=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_VERSION" \
                "$PHASE4_ROGUE_TRANSFERS")
            case "$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" in
                abort|target_config_abort|uri_policy_abort|target_handler_abort)
                    # The enforced normal-redirect boundary closes the
                    # connection/stream after keeping all response bytes
                    # private. curl can therefore report a transport error;
                    # it is evidence of the expected fail-closed result, not
                    # a test failure. A successful curl transfer must still
                    # have negotiated H2 and produced a concrete outcome.
                    if [ "$curl_rc" -eq 0 ]; then
                        [ -n "$http_status" ] || \
                            fail "Phase-4 internal redirect H2 abort returned no status despite curl success"
                        [ "$http_version" = "2" ] || \
                            fail "Phase-4 internal redirect H2 abort fell back from HTTP/2"
                    fi
                    ;;
                *)
                    [ "$curl_rc" -eq 0 ] || \
                        fail "Phase-4 internal redirect H2 client failed rc=$curl_rc"
                    [ "$http_version" = "2" ] || \
                        fail "Phase-4 internal redirect TLS client did not negotiate HTTP/2"
                    ;;
            esac
            grep -F "$HTTP2_PROTOCOL_LABEL" "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 internal redirect H2 trace lacks HTTP/2 evidence"
            grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN" \
                "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 internal redirect H2 trace lacks ALPN h2 acceptance evidence"
            ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
    esac
    grep -F 'ModSecurity Phase4 redirect test issued an internal redirect' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 internal redirect test handler did not issue its redirect"
    assert_phase4_internal_redirect_target_handler_was_not_run

    case "$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" in
        bypass)
            [ "$http_status" = "200" ] || \
                fail "Phase-4 internal redirect bypass expected status 200, observed $http_status"
            case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
                http1) assert_single_h1_status 200 ;;
                h2) assert_single_h2_status 200 ;;
                *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
            esac
            cmp -s "$redirect_expected" "$RESPONSE_BODY" || \
                fail "Phase-4 internal redirect bypass did not expose the original marker body"
            if [ -s "$APACHE_PHASE4_LOG_FILE" ] && \
                grep -F '"rule_id":"2190401"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1; then
                fail "Phase-4 internal redirect bypass unexpectedly recorded a Phase-4 rule decision"
            fi
            if [ -s "$AUDIT_LOG_FILE" ] && \
                grep -F '2190401' "$AUDIT_LOG_FILE" >/dev/null 2>&1; then
                fail "Phase-4 internal redirect bypass unexpectedly audited Phase-4 rule 2190401"
            fi
            ;;
        target_config_bypass)
            [ "$http_status" = "200" ] || \
                fail "Phase-4 target configuration redirect bypass expected status 200, observed $http_status"
            assert_single_h1_status 200
            cmp -s "$redirect_expected" "$RESPONSE_BODY" || \
                fail "Phase-4 target configuration redirect bypass did not expose the marker body"
            redirect_direct_rule_events_after=$(phase4_redirect_direct_rule_event_count \
                "$APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID")
            [ "$redirect_direct_rule_events_after" -eq \
                "$redirect_direct_rule_events_before" ] || \
                fail "Phase-4 target configuration redirect bypass unexpectedly evaluated rule 2190410"
            ;;
        target_config_abort)
            case "$http_status" in
                2*) fail "Phase-4 target configuration redirect was released as successful status $http_status" ;;
                *) ;;
            esac
            if grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1; then
                fail "Phase-4 target configuration redirect abort leaked the marker body"
            fi
            grep -F "$PHASE4_TRANSACTION_REBIND_REFUSAL" \
                "$LOG_DIR/error.log" >/dev/null 2>&1 || \
                fail "Phase-4 target configuration redirect lacks the transaction-rebind refusal"
            redirect_direct_rule_events_after=$(phase4_redirect_direct_rule_event_count \
                "$APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID")
            [ "$redirect_direct_rule_events_after" -eq \
                "$redirect_direct_rule_events_before" ] || \
                fail "Phase-4 target configuration redirect incorrectly ran rule $APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID on a rebound transaction"
            ;;
        uri_policy_bypass)
            [ "$http_status" = "200" ] || \
                fail "Phase-4 URI policy redirect bypass expected status 200, observed $http_status"
            assert_single_h1_status 200
            cmp -s "$redirect_expected" "$RESPONSE_BODY" || \
                fail "Phase-4 URI policy redirect bypass did not expose the marker body"
            redirect_direct_rule_events_after=$(phase4_redirect_direct_rule_event_count \
                "$APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID")
            [ "$redirect_direct_rule_events_after" -eq \
                "$redirect_direct_rule_events_before" ] || \
                fail "Phase-4 URI policy redirect bypass unexpectedly evaluated rule $APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID"
            ;;
        uri_policy_abort)
            case "$http_status" in
                2*) fail "Phase-4 URI policy redirect was released as successful status $http_status" ;;
                *) ;;
            esac
            if grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1; then
                fail "Phase-4 URI policy redirect abort leaked the marker body"
            fi
            grep -F "$PHASE4_TRANSACTION_REBIND_REFUSAL" \
                "$LOG_DIR/error.log" >/dev/null 2>&1 || \
                fail "Phase-4 URI policy redirect lacks the transaction-rebind refusal"
            redirect_direct_rule_events_after=$(phase4_redirect_direct_rule_event_count \
                "$APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID")
            [ "$redirect_direct_rule_events_after" -eq \
                "$redirect_direct_rule_events_before" ] || \
                fail "Phase-4 URI policy redirect incorrectly ran rule $APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID on a rebound transaction"
            ;;
        target_handler_abort)
            case "$http_status" in
                2*) fail "Phase-4 target-handler redirect was released as successful status $http_status" ;;
                *) ;;
            esac
            if grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1; then
                fail "Phase-4 target-handler redirect abort leaked the marker body"
            fi
            grep -F "$PHASE4_TRANSACTION_REBIND_REFUSAL" \
                "$LOG_DIR/error.log" >/dev/null 2>&1 || \
                fail "Phase-4 target-handler redirect lacks the transaction-rebind refusal"
            assert_phase4_internal_redirect_target_handler_was_not_run
            ;;
        abort)
            case "$http_status" in
                2*) fail "Phase-4 internal redirect was released as successful status $http_status" ;;
                *) ;;
            esac
            if grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1; then
                fail "Phase-4 internal redirect abort leaked the marker body"
            fi
            grep -F "$PHASE4_TRANSACTION_REBIND_REFUSAL" \
                "$LOG_DIR/error.log" >/dev/null 2>&1 || \
                fail "Phase-4 internal redirect abort lacks the transaction-rebind refusal"
            ;;
        *) fail "unsupported APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT=$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" ;;
    esac
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
}

send_phase4_downstream_error_request() {
    case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
        http1)
            : > "$RESPONSE_BODY"
            set +e
            http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
                -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
                "http://127.0.0.1:$PORT/__phase4_downstream_error")
            curl_rc=$?
            set -e
            [ "$curl_rc" -ne 0 ] || \
                fail "Phase-4 downstream error must abort the post-commit response"
            ;;
        h2)
            "$CURL_BIN" --version | grep -E "$CURL_HTTP2_FEATURE_PATTERN" >/dev/null 2>&1 || \
                blocked "curl lacks HTTP/2 support required for the Phase-4 downstream error H2 test"
            : > "$RESPONSE_BODY"
            : > "$RESPONSE_HEADERS"
            set +e
            "$CURL_BIN" -sS -k --http2 --trace-ids \
                --trace-ascii "$PHASE4_ROGUE_TRACE" \
                -D "$RESPONSE_HEADERS" -o "$RESPONSE_BODY" \
                -w "$CURL_HTTP_STATUS_VERSION_FORMAT" \
                "https://127.0.0.1:$PORT/__phase4_downstream_error" \
                > "$PHASE4_ROGUE_TRANSFERS" \
                2> "$LOG_DIR/phase4-downstream-error-h2-client.err"
            curl_rc=$?
            set -e
            [ "$curl_rc" -ne 0 ] || \
                fail "Phase-4 downstream error must abort the post-commit response"
            grep -F "$HTTP2_PROTOCOL_LABEL" "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 downstream error H2 trace lacks HTTP/2 evidence"
            grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN" \
                "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 downstream error H2 trace lacks ALPN h2 acceptance evidence"
            ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
    esac

    [ ! -s "$RESPONSE_HEADERS" ] || \
        fail "Phase-4 downstream error exposed response headers after the abort boundary"
    [ ! -s "$RESPONSE_BODY" ] || \
        fail "Phase-4 downstream error exposed a response body after the abort boundary"
    if grep -F 'phase4-allow-before-downstream-error' \
        "$RESPONSE_BODY" >/dev/null 2>&1; then
        fail "Phase-4 downstream error leaked the allowed pre-error response body"
    fi
    grep -F 'ModSecurity Phase4 downstream error test replaced the released response with an error bucket' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 downstream error filter did not replace the released response"
    grep -F '"event":"connector_error"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
        fail "Phase-4 downstream error lacks the canonical connector-error event"
    grep -F '"actual_action":"abort_connection"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
        fail "Phase-4 downstream error lacks the canonical abort action"
    grep -F '"connection_aborted":true' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
        fail "Phase-4 downstream error lacks the aborted-connection event flag"
    grep -F '"transport_result":"connection_aborted"' "$APACHE_PHASE4_LOG_FILE" >/dev/null 2>&1 || \
        fail "Phase-4 downstream error lacks the aborted-connection transport result"
    printf '%s\n' '0' > "$LOG_DIR/observed-status.txt"
    printf '%s\n' 'connection_aborted' > "$LOG_DIR/observed-transport-result.txt"
}


send_phase4_upstream_error_request() {
    upstream_error_expected="$LOG_DIR/phase4-upstream-error.expected"

    printf '%s' 'phase4-downstream-error-document' > "$upstream_error_expected"
    case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
        http1)
            : > "$RESPONSE_BODY"
            set +e
            http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
                -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
                "http://127.0.0.1:$PORT/__phase4_upstream_error")
            curl_rc=$?
            set -e
            [ "$curl_rc" -eq 0 ] || \
                fail "Phase-4 upstream error H1 client failed rc=$curl_rc"
            ;;
        h2)
            "$CURL_BIN" --version | grep -E "$CURL_HTTP2_FEATURE_PATTERN" >/dev/null 2>&1 || \
                blocked "curl lacks HTTP/2 support required for the Phase-4 upstream error H2 test"
            : > "$RESPONSE_BODY"
            : > "$RESPONSE_HEADERS"
            set +e
            "$CURL_BIN" -sS -k --http2 --trace-ids \
                --trace-ascii "$PHASE4_ROGUE_TRACE" \
                -D "$RESPONSE_HEADERS" -o "$RESPONSE_BODY" \
                -w "$CURL_HTTP_STATUS_VERSION_FORMAT" \
                "https://127.0.0.1:$PORT/__phase4_upstream_error" \
                > "$PHASE4_ROGUE_TRANSFERS" \
                2> "$LOG_DIR/phase4-upstream-error-h2-client.err"
            curl_rc=$?
            set -e
            [ "$curl_rc" -eq 0 ] || \
                fail "Phase-4 upstream error H2 client failed rc=$curl_rc"
            http_status=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_STATUS" \
                "$PHASE4_ROGUE_TRANSFERS")
            http_version=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_VERSION" \
                "$PHASE4_ROGUE_TRANSFERS")
            [ "$http_version" = "2" ] || \
                fail "Phase-4 upstream error TLS client did not negotiate HTTP/2"
            grep -F "$HTTP2_PROTOCOL_LABEL" "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 upstream error H2 trace lacks HTTP/2 evidence"
            grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN" \
                "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 upstream error H2 trace lacks ALPN h2 acceptance evidence"
            ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
    esac

    [ "$http_status" = "500" ] || \
        fail "Phase-4 upstream error expected status 500, observed $http_status"
    case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
        http1) assert_single_h1_status 500 ;;
        h2) assert_single_h2_status 500 ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
    esac
    cmp -s "$upstream_error_expected" "$RESPONSE_BODY" || \
        fail "Phase-4 upstream error did not produce the sole configured ErrorDocument body"
    assert_phase4_error_document_headers "$upstream_error_expected" 500
    grep -F 'ModSecurity Phase4 upstream error test issued a first error bucket' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 upstream error handler did not issue its first error bucket"
    if grep -F 'failed to set aside response brigade' "$LOG_DIR/error.log" >/dev/null 2>&1; then
        fail "Phase-4 upstream error reached the generic setaside failure instead of the first-error branch"
    fi
    if grep -F 'refusing normal internal redirect across the Phase 4 response boundary' \
        "$LOG_DIR/error.log" >/dev/null 2>&1; then
        fail "Phase-4 upstream ErrorDocument was mistaken for a normal redirect"
    fi
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
}


send_phase4_nested_error_document_redirect_request() {
    : > "$RESPONSE_BODY"
    set +e
    http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
        -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
        "http://127.0.0.1:$PORT/__phase4_rogue")
    curl_rc=$?
    set -e

    # The second redirect crosses back into an unbound producer target. It
    # may therefore terminate H1 before a status line is completed; a curl
    # transport error is the expected fail-closed result, while any completed
    # response must not be successful or carry either protected body.
    case "$http_status" in
        2*) fail "nested ErrorDocument redirect was released as successful status $http_status" ;;
        *) ;;
    esac
    if grep -F "$PHASE4_RESPONSE_BODY_MARKER" "$RESPONSE_BODY" >/dev/null 2>&1 || \
        grep -F 'phase4-rogue-prefix-' "$RESPONSE_BODY" >/dev/null 2>&1; then
        fail "nested ErrorDocument redirect leaked a protected response body"
    fi
    grep -F 'ModSecurity Phase4 nested ErrorDocument test issued a second internal redirect' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "nested ErrorDocument test handler did not issue its second redirect"
    grep -F "$PHASE4_TRANSACTION_REBIND_REFUSAL" \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "nested ErrorDocument redirect lacks the transaction-rebind refusal"
    assert_phase4_rogue_evidence
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    if [ "$curl_rc" -eq 0 ]; then
        printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
    else
        printf '%s\n' 'client_abort' > "$LOG_DIR/observed-transport-result.txt"
    fi
}


send_phase4_preoutput_error_document_request() {
    preoutput_private_body='phase4-preoutput-error-document-private'

    case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
        http1)
            : > "$RESPONSE_BODY"
            set +e
            http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
                -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
                "http://127.0.0.1:$PORT/__phase4_preoutput_error")
            curl_rc=$?
            set -e
            ;;
        h2)
            "$CURL_BIN" --version | grep -E "$CURL_HTTP2_FEATURE_PATTERN" >/dev/null 2>&1 || \
                blocked "curl lacks HTTP/2 support required for the pre-output ErrorDocument H2 test"
            : > "$RESPONSE_BODY"
            : > "$RESPONSE_HEADERS"
            set +e
            "$CURL_BIN" -sS -k --http2 --trace-ids \
                --trace-ascii "$PHASE4_ROGUE_TRACE" \
                -D "$RESPONSE_HEADERS" -o "$RESPONSE_BODY" \
                -w "$CURL_HTTP_STATUS_VERSION_FORMAT" \
                "https://127.0.0.1:$PORT/__phase4_preoutput_error" \
                > "$PHASE4_ROGUE_TRANSFERS" \
                2> "$LOG_DIR/phase4-preoutput-error-document-h2-client.err"
            curl_rc=$?
            set -e
            http_status=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_STATUS" \
                "$PHASE4_ROGUE_TRANSFERS")
            http_version=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_VERSION" \
                "$PHASE4_ROGUE_TRANSFERS")
            if [ "$curl_rc" -eq 0 ]; then
                [ "$http_version" = "2" ] || \
                    fail "pre-output ErrorDocument abort fell back from HTTP/2"
            fi
            grep -F "$HTTP2_PROTOCOL_LABEL" "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "pre-output ErrorDocument H2 trace lacks HTTP/2 evidence"
            grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN" \
                "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "pre-output ErrorDocument H2 trace lacks ALPN h2 acceptance evidence"
            ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
    esac

    case "$http_status" in
        2*) fail "pre-output ErrorDocument redirect was released as successful status $http_status" ;;
        *) ;;
    esac
    if grep -F "$preoutput_private_body" "$RESPONSE_BODY" >/dev/null 2>&1; then
        fail "pre-output ErrorDocument redirect leaked its private target body"
    fi
    grep -F 'ModSecurity Phase4 preoutput ErrorDocument test returned HTTP_NOT_FOUND before any response brigade' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "pre-output ErrorDocument test handler did not return HTTP_NOT_FOUND"
    grep -F "$PHASE4_TRANSACTION_REBIND_REFUSAL" \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "pre-output ErrorDocument redirect lacks the transaction-rebind refusal"
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    if [ "$curl_rc" -eq 0 ]; then
        printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
    else
        printf '%s\n' 'client_abort' > "$LOG_DIR/observed-transport-result.txt"
    fi
}


send_phase4_fragmented_buckets_request() {
    : > "$RESPONSE_BODY"
    set +e
    http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
        -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
        "http://127.0.0.1:$PORT/__phase4_fragmented_buckets")
    curl_rc=$?
    set -e

    [ "$curl_rc" -eq 0 ] || \
        fail "Phase-4 fragmented-bucket H1 client failed rc=$curl_rc"
    [ "$http_status" = "500" ] || \
        fail "Phase-4 fragmented-bucket limit expected status 500, observed $http_status"
    assert_single_h1_status 500
    if grep -F 'ffffffffffffffff' "$RESPONSE_BODY" >/dev/null 2>&1; then
        fail "Phase-4 fragmented-bucket limit leaked the retained response body"
    fi
    grep -F 'response brigade exceeds modsecurity_phase4_bucket_limit' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 fragmented-bucket limit did not record its fail-closed reason"
    grep -F 'ModSecurity Phase4 fragmented-bucket test emitted 4097 one-byte buckets' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 fragmented-bucket handler did not execute"
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
}


send_phase4_fragmented_bucket_boundary_request() {
    : > "$RESPONSE_BODY"
    set +e
    http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
        -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
        "http://127.0.0.1:$PORT/__phase4_fragmented_buckets_boundary")
    curl_rc=$?
    set -e

    [ "$curl_rc" -eq 0 ] || \
        fail "Phase-4 fragmented-bucket boundary H1 client failed rc=$curl_rc"
    [ "$http_status" = "200" ] || \
        fail "Phase-4 fragmented-bucket boundary expected status 200, observed $http_status"
    assert_single_h1_status 200
    body_size=$(wc -c < "$RESPONSE_BODY" | tr -d '[:space:]')
    [ "$body_size" = "4095" ] || \
        fail "Phase-4 fragmented-bucket boundary expected 4095 bytes, observed $body_size"
    if LC_ALL=C tr -d 'f' < "$RESPONSE_BODY" | grep . >/dev/null 2>&1; then
        fail "Phase-4 fragmented-bucket boundary returned a non-fragment marker byte"
    fi
    if grep -F 'response brigade exceeds modsecurity_phase4_bucket_limit' \
        "$LOG_DIR/error.log" >/dev/null 2>&1; then
        fail "Phase-4 fragmented-bucket boundary unexpectedly hit the limit"
    fi
    grep -F 'ModSecurity Phase4 fragmented-bucket test emitted 4095 one-byte buckets in two brigades rc=0' \
        "$LOG_DIR/error.log" >/dev/null 2>&1 || \
        fail "Phase-4 fragmented-bucket boundary handler did not complete"
    printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
    printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
}


phase4_terminal_test_uses_h2() {
    [ "$APACHE_PHASE4_ROGUE_PROTOCOL" = "h2" ] || return 1
    [ "$APACHE_PHASE4_ROGUE_TEST" = "1" ] || \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TEST" = "1" ] || \
        [ "$APACHE_PHASE4_DOWNSTREAM_ERROR_TEST" = "1" ] || \
        [ "$APACHE_PHASE4_UPSTREAM_ERROR_TEST" = "1" ] || \
        [ "$APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST" = "1" ]
}

send_phase4_rogue_request() {
    rogue_path=/__phase4_rogue
    if [ "$APACHE_PHASE4_ROGUE_HEADER_MUTATION" = "1" ]; then
        rogue_path=/__phase4_rogue_header
    fi
    case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
        http1)
            : > "$RESPONSE_BODY"
            set +e
            http_status=$("$CURL_BIN" -sS --http1.1 -D "$RESPONSE_HEADERS" \
                -o "$RESPONSE_BODY" -w "$CURL_HTTP_STATUS_FORMAT" \
                "http://127.0.0.1:$PORT$rogue_path")
            curl_rc=$?
            set -e
            [ "$curl_rc" -eq 0 ] || \
                fail "Phase-4 rogue H1 client failed rc=$curl_rc"
            case "$APACHE_PHASE4_ROGUE_EXPECT" in
                deny)
                    [ "$http_status" = "403" ] || \
                        fail "Phase-4 rogue H1 expected status 403, observed $http_status"
                    assert_single_h1_status 403
                    assert_phase4_rogue_no_leak "$RESPONSE_BODY"
                    if [ "$APACHE_PHASE4_ERROR_DOCUMENT" = "1" ]; then
                        assert_phase4_rogue_error_document "$RESPONSE_BODY"
                    fi
                    ;;
                allow)
                    [ "$http_status" = "200" ] || \
                        fail "Phase-4 rogue H1 allow expected status 200, observed $http_status"
                    assert_single_h1_status 200
                    assert_phase4_rogue_allow_body "$RESPONSE_BODY"
                    if [ "$APACHE_PHASE4_ROGUE_HEADER_MUTATION" = "1" ]; then
                        assert_phase3_header_freeze_headers "$RESPONSE_HEADERS"
                    fi
                    ;;
                *) fail "unsupported APACHE_PHASE4_ROGUE_EXPECT=$APACHE_PHASE4_ROGUE_EXPECT" ;;
            esac
            assert_phase4_rogue_evidence
            printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
            printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
            ;;
        h2)
            "$CURL_BIN" --version | grep -E "$CURL_HTTP2_FEATURE_PATTERN" >/dev/null 2>&1 || \
                blocked "curl lacks HTTP/2 support required for the Phase-4 rogue H2 test"
            if [ "$APACHE_PHASE4_ROGUE_HEADER_MUTATION" = "1" ]; then
                [ "$APACHE_PHASE4_ROGUE_EXPECT" = "allow" ] || \
                    fail "Phase-3 header-freeze H2 requires allow expectation"
                [ "$APACHE_PHASE4_ROGUE_PHASE" = "p3" ] || \
                    fail "Phase-3 header-freeze H2 requires a Phase-3 rule"
                : > "$RESPONSE_BODY"
                : > "$RESPONSE_HEADERS"
                set +e
                "$CURL_BIN" -sS -k --http2 --trace-ids \
                    --trace-ascii "$PHASE4_ROGUE_TRACE" \
                    -D "$RESPONSE_HEADERS" -o "$RESPONSE_BODY" \
                    -w "$CURL_HTTP_STATUS_VERSION_FORMAT" \
                    "https://127.0.0.1:$PORT$rogue_path" \
                    > "$PHASE4_ROGUE_TRANSFERS" \
                    2> "$LOG_DIR/phase4-rogue-h2-client.err"
                curl_rc=$?
                set -e
                [ "$curl_rc" -eq 0 ] || \
                    fail "Phase-3 header-freeze H2 client failed rc=$curl_rc"
                rogue_status=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_STATUS" \
                    "$PHASE4_ROGUE_TRANSFERS")
                rogue_version=$(awk -F '\t' "$AWK_FIRST_TAB_RECORD_VERSION" \
                    "$PHASE4_ROGUE_TRANSFERS")
                [ "$rogue_status" = "200" ] || \
                    fail "Phase-3 header-freeze H2 expected status 200, observed ${rogue_status:-missing}"
                [ "$rogue_version" = "2" ] || \
                    fail "Phase-3 header-freeze TLS client did not negotiate HTTP/2"
                grep -F "$HTTP2_PROTOCOL_LABEL" "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                    fail "Phase-3 header-freeze H2 trace lacks HTTP/2 evidence"
                grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN" \
                    "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                    fail "Phase-3 header-freeze H2 trace lacks ALPN h2 acceptance evidence"
                assert_phase4_rogue_allow_body "$RESPONSE_BODY"
                assert_phase3_header_freeze_headers "$RESPONSE_HEADERS"
                assert_phase4_rogue_evidence
                printf '%s\n' "$rogue_status" > "$LOG_DIR/observed-status.txt"
                printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
                return 0
            fi
            [ "$APACHE_PHASE4_ROGUE_EXPECT" = "deny" ] || \
                fail "Phase-4 rogue H2 currently requires deny expectation"
            [ "$APACHE_PHASE4_ROGUE_PHASE" = "p4" ] || \
                fail "Phase-4 rogue H2 currently requires a Phase-4 rule"
            rogue_url="https://127.0.0.1:$PORT/__phase4_rogue"
            allow_url="https://127.0.0.1:$PORT/__phase4_rogue_allow.txt"
            : > "$PHASE4_ROGUE_RESPONSE_BODY"
            : > "$PHASE4_ROGUE_ALLOW_BODY"
            set +e
            # Keep the allow URL after the denied producer URL in one curl
            # transfer.  Matching conn_id values then prove that a Phase-4
            # terminal denial did not poison the physical H2 connection or a
            # later independent request after the denial completed.
            "$CURL_BIN" -sS -k --http2 --trace-ids --trace-ascii "$PHASE4_ROGUE_TRACE" \
                -o "$PHASE4_ROGUE_RESPONSE_BODY" \
                -o "$PHASE4_ROGUE_ALLOW_BODY" \
                -w '%{url_effective}\t%{http_code}\t%{http_version}\t%{conn_id}\n' \
                "$rogue_url" "$allow_url" > "$PHASE4_ROGUE_TRANSFERS" \
                2> "$LOG_DIR/phase4-rogue-h2-client.err"
            curl_rc=$?
            set -e
            [ "$curl_rc" -eq 0 ] || \
                fail "Phase-4 rogue H2 client failed rc=$curl_rc"
            rogue_status=$(awk -F '\t' '$1 ~ /\/__phase4_rogue$/ { print $2; exit }' "$PHASE4_ROGUE_TRANSFERS")
            rogue_version=$(awk -F '\t' '$1 ~ /\/__phase4_rogue$/ { print $3; exit }' "$PHASE4_ROGUE_TRANSFERS")
            rogue_connection=$(awk -F '\t' '$1 ~ /\/__phase4_rogue$/ { print $4; exit }' "$PHASE4_ROGUE_TRANSFERS")
            allow_status=$(awk -F '\t' '$1 ~ /\/__phase4_rogue_allow\.txt$/ { print $2; exit }' "$PHASE4_ROGUE_TRANSFERS")
            allow_version=$(awk -F '\t' '$1 ~ /\/__phase4_rogue_allow\.txt$/ { print $3; exit }' "$PHASE4_ROGUE_TRANSFERS")
            allow_connection=$(awk -F '\t' '$1 ~ /\/__phase4_rogue_allow\.txt$/ { print $4; exit }' "$PHASE4_ROGUE_TRANSFERS")
            [ "$rogue_status" = "403" ] || \
                fail "Phase-4 rogue H2 expected denied stream status 403, observed ${rogue_status:-missing}"
            [ "$allow_status" = "200" ] || \
                fail "Phase-4 rogue H2 independent allow stream expected 200, observed ${allow_status:-missing}"
            [ "$rogue_version" = "2" ] && [ "$allow_version" = "2" ] || \
                fail "Phase-4 rogue TLS client did not negotiate HTTP/2 for both streams"
            [ -n "$rogue_connection" ] && [ "$rogue_connection" = "$allow_connection" ] || \
                fail "Phase-4 rogue H2 allow request did not reuse the connection after denial"
            grep -F "$HTTP2_PROTOCOL_LABEL" "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 rogue H2 trace lacks HTTP/2 evidence"
            grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN" \
                "$PHASE4_ROGUE_TRACE" >/dev/null 2>&1 || \
                fail "Phase-4 rogue H2 trace lacks ALPN h2 acceptance evidence"
            assert_phase4_rogue_no_leak "$PHASE4_ROGUE_RESPONSE_BODY"
            allow_body=$(cat "$PHASE4_ROGUE_ALLOW_BODY")
            [ "$allow_body" = 'phase4-rogue-allow-body' ] || \
                fail "Phase-4 rogue H2 allow stream body was lost or changed"
            if [ "$APACHE_PHASE4_ERROR_DOCUMENT" = "1" ]; then
                assert_phase4_rogue_error_document "$PHASE4_ROGUE_RESPONSE_BODY"
            fi
            assert_phase4_rogue_evidence
            printf '%s\n' "$rogue_status" > "$LOG_DIR/observed-status.txt"
            printf '%s\n' "$OBSERVED_TRANSPORT_HTTP_STATUS" > "$LOG_DIR/observed-transport-result.txt"
            ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
    esac
}

quote_request_path() {
    request_path=$1
    "$PYTHON_BIN" - "$request_path" <<'PY'
import sys
from urllib.parse import quote

print(quote(sys.argv[1], safe="/:?&=%+$,;@[]!'()*"))
PY
}

response_header_backend_needed() {
    [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ] && return 0
    grep -Eqi '(^|[^[:alnum:]_])RESPONSE_HEADERS([[:space:]:]|$)' "$RULES_FILE"
}

start_response_header_backend() {
    response_header_backend_needed || return 0
    if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then
        start_synchronized_upstream
        return 0
    fi
    RESPONSE_HEADER_BACKEND_PORT=$(select_free_port $((PORT + 1000)) "$PORT_SEARCH_LIMIT") || \
        blocked "no free response-header backend port found"
    "$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/response-header-test-backend.py" \
        --port "$RESPONSE_HEADER_BACKEND_PORT" \
        --body-file "$DOCROOT/index.html" \
        --safe-root "$RUNTIME_ROOT" \
        --fixture-file "$RESPONSE_HEADER_FIXTURE_FILE" \
        >"$LOG_DIR/response-header-backend.stdout.log" \
        2>"$LOG_DIR/response-header-backend.stderr.log" &
    RESPONSE_HEADER_BACKEND_PID=$!
    wait_tcp_port "$RESPONSE_HEADER_BACKEND_PORT" || blocked "response-header backend failed to start"
}

write_backend_proxy_directives() {
    output=$1
    : > "$output"
    response_header_backend_needed || return 0
    {
        echo "# Generated proxy route for response-header smoke cases."
        echo "<IfModule proxy_module>"
        echo "<IfModule proxy_http_module>"
        echo "ProxyPass \"/__modsec_smoke_ready\" \"!\""
        # Keep terminal-response test handlers and their local ErrorDocument
        # fixtures out of the catch-all response-header backend route. Apache
        # applies these exclusions by complete local route, rather than by a
        # synthetic prefix used only by this harness.
        echo "ProxyPass \"/__phase4_rogue_header\" \"!\""
        echo "ProxyPass \"/__phase4_rogue\" \"!\""
        echo "ProxyPass \"/__phase4_fragmented_buckets\" \"!\""
        echo "ProxyPass \"/__phase4_fragmented_buckets_boundary\" \"!\""
        echo "ProxyPass \"/__phase4_internal_redirect\" \"!\""
        echo "ProxyPass \"/__phase4_internal_redirect_target.txt\" \"!\""
        echo "ProxyPass \"/__phase4_internal_redirect_target_handler_test\" \"!\""
        echo "ProxyPass \"/__phase4_internal_redirect_target_handler_target\" \"!\""
        echo "ProxyPass \"/__phase4_nested_error_document_redirect\" \"!\""
        echo "ProxyPass \"/__phase4_preoutput_error\" \"!\""
        echo "ProxyPass \"/__phase4_preoutput_error_document.txt\" \"!\""
        echo "ProxyPass \"/__phase4_downstream_error\" \"!\""
        echo "ProxyPass \"/__phase4_upstream_error\" \"!\""
        echo "ProxyPass \"/__phase4_error_document.txt\" \"!\""
        echo "ProxyPass \"/__phase4_rogue_allow.txt\" \"!\""
        echo "ProxyPass \"/\" \"http://127.0.0.1:$RESPONSE_HEADER_BACKEND_PORT/\""
        echo "ProxyPassReverse \"/\" \"http://127.0.0.1:$RESPONSE_HEADER_BACKEND_PORT/\""
        echo "$IFMODULE_END"
        echo "$IFMODULE_END"
    } > "$output"
}

write_phase4_terminal_test_support() {
    : > "$APACHE_PHASE4_EXTRA_CONFIG"

    case "$APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST must be 0 or 1" ;;
    esac
    if [ "$APACHE_PHASE4_ERROR_DOCUMENT" = "1" ] && \
        [ "$APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST" = "1" ]; then
        fail "normal and nested Phase-4 ErrorDocument tests are mutually exclusive"
    fi

    case "$APACHE_PHASE4_ERROR_DOCUMENT" in
        0) ;;
        1)
            printf '%s\n' 'phase4-custom-deny-body' > \
                "$DOCROOT/__phase4_error_document.txt"
            printf '%s\n' \
                'ErrorDocument 403 /__phase4_error_document.txt' \
                >> "$APACHE_PHASE4_EXTRA_CONFIG"
            ;;
        *) fail "APACHE_PHASE4_ERROR_DOCUMENT must be 0 or 1" ;;
    esac

    if [ "$APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST" = "1" ]; then
        printf '%s\n' \
            'ErrorDocument 403 /__phase4_nested_error_document_redirect' \
            >> "$APACHE_PHASE4_EXTRA_CONFIG"
    fi
    if [ "$APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST" = "1" ]; then
        printf '%s' 'phase4-preoutput-error-document-private' > \
            "$DOCROOT/__phase4_preoutput_error_document.txt"
        printf '%s\n' \
            'ErrorDocument 404 /__phase4_preoutput_error_document.txt' \
            >> "$APACHE_PHASE4_EXTRA_CONFIG"
    fi

    case "$APACHE_PHASE4_ROGUE_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_ROGUE_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_INTERNAL_REDIRECT_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_INTERNAL_REDIRECT_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_DOWNSTREAM_ERROR_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_DOWNSTREAM_ERROR_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_UPSTREAM_ERROR_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_UPSTREAM_ERROR_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST" in
        0|1) ;;
        *) fail "APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST must be 0 or 1" ;;
    esac
    if [ "$APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST" = "1" ] && \
        [ "$APACHE_PHASE4_ROGUE_TEST" != "1" ]; then
        fail "nested Phase-4 ErrorDocument test requires APACHE_PHASE4_ROGUE_TEST=1"
    fi
    if [ "$APACHE_PHASE4_ROGUE_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_DOWNSTREAM_ERROR_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_UPSTREAM_ERROR_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST" = "0" ] && \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" = "0" ]; then
        return 0
    fi
    case "$APACHE_PHASE4_ROGUE_EXPECT" in
        deny|allow) ;;
        *) fail "APACHE_PHASE4_ROGUE_EXPECT must be deny or allow" ;;
    esac
    case "$APACHE_PHASE4_ROGUE_PHASE" in
        p3|p4) ;;
        *) fail "APACHE_PHASE4_ROGUE_PHASE must be p3 or p4" ;;
    esac
    case "$APACHE_PHASE4_ROGUE_HEADER_MUTATION" in
        0|1) ;;
        *) fail "APACHE_PHASE4_ROGUE_HEADER_MUTATION must be 0 or 1" ;;
    esac
    case "$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" in
        bypass|abort|target_config_bypass|target_config_abort|uri_policy_bypass|uri_policy_abort|target_handler_abort) ;;
        *) fail "unsupported APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT=$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" ;;
    esac
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ] && \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TEST" != "1" ]; then
        fail "target configuration redirect test requires APACHE_PHASE4_INTERNAL_REDIRECT_TEST=1"
    fi
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST" = "1" ] && \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TEST" != "1" ]; then
        fail "URI policy redirect test requires APACHE_PHASE4_INTERNAL_REDIRECT_TEST=1"
    fi
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" = "1" ] && \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TEST" != "1" ]; then
        fail "target-handler redirect test requires APACHE_PHASE4_INTERNAL_REDIRECT_TEST=1"
    fi
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ] && \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST" = "1" ]; then
        fail "target configuration and URI policy redirect controls are mutually exclusive"
    fi
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" = "1" ] && \
        { [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ] || \
          [ "$APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST" = "1" ]; }; then
        fail "target-handler redirect test is mutually exclusive with target configuration and URI policy controls"
    fi
    case "$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" in
        target_config_bypass|target_config_abort)
            [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ] || \
                fail "target configuration redirect expectation requires its target config test"
            ;;
        uri_policy_bypass|uri_policy_abort)
            [ "$APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST" = "1" ] || \
                fail "URI policy redirect expectation requires its URI policy test"
            ;;
        target_handler_abort)
            [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" = "1" ] || \
                fail "target-handler redirect expectation requires its target-handler test"
            ;;
        bypass|abort) ;;
        *) fail "unsupported APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT=$APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT" ;;
    esac
    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ] || \
        [ "$APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST" = "1" ]; then
        case "$APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID" in
            ''|*[!0-9]*) fail "APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID must be a numeric rule ID" ;;
            *) ;;
        esac
    fi

    if [ "$APACHE_PHASE4_DOWNSTREAM_ERROR_TEST" = "1" ] || \
        [ "$APACHE_PHASE4_UPSTREAM_ERROR_TEST" = "1" ]; then
        printf '%s' 'phase4-downstream-error-document' > \
            "$DOCROOT/__phase4_downstream_error_document.txt"
        printf '%s\n' \
            'ErrorDocument 500 /__phase4_downstream_error_document.txt' \
            >> "$APACHE_PHASE4_EXTRA_CONFIG"
    fi

    if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ]; then
        {
            printf '%s\n' 'SecAuditEngine On'
            printf 'SecAuditLog "%s"\n' "$AUDIT_LOG_FILE"
            phase4_redirect_rule="SecRule RESPONSE_BODY \"@contains $PHASE4_RESPONSE_BODY_MARKER\" \"id:2190410,phase:4,deny,status:403,log,t:none,msg:'Apache Phase-4 target configuration redirect deny regression'\""
            printf '%s\n' "$phase4_redirect_rule"
        } > "$APACHE_PHASE4_REDIRECT_TARGET_RULES_FILE"
    fi

    [ -x "$APXS_BIN" ] || blocked "missing APXS for Phase-4 rogue test: $APXS_BIN"
    [ -f "$SCRIPT_DIR/mod_phase4_terminal_rogue.c" ] || \
        blocked "missing Phase-4 rogue test source"
    prepare_runtime_directory "$RUNTIME_ROOT/modules" "Apache runtime modules" 1
    cp "$SCRIPT_DIR/mod_phase4_terminal_rogue.c" "$PHASE4_ROGUE_SOURCE" || \
        not_executable "could not stage Phase-4 rogue test source"
    if ! "$APXS_BIN" -c -o "$PHASE4_ROGUE_OUTPUT" \
        "$PHASE4_ROGUE_SOURCE" \
        > "$LOG_DIR/phase4-rogue-apxs.log" 2>&1; then
        not_executable "could not build Phase-4 rogue test module; see $LOG_DIR/phase4-rogue-apxs.log"
    fi
    [ -f "$PHASE4_ROGUE_MODULE" ] || \
        not_executable "APXS did not produce the Phase-4 rogue test module"
    printf '%s\n' 'phase4-rogue-allow-body' > \
        "$DOCROOT/__phase4_rogue_allow.txt"
    printf '%s' "$PHASE4_RESPONSE_BODY_MARKER" > \
        "$DOCROOT/__phase4_internal_redirect_target.txt"
    {
        printf 'LoadModule phase4_terminal_rogue_module "%s"\n' "$PHASE4_ROGUE_MODULE"
        printf '%s\n' '<Location "/__phase4_rogue">'
        printf '%s\n' '    SetHandler phase4-terminal-rogue'
        printf '%s\n' "$APACHE_LOCATION_END"
        printf '%s\n' '<Location "/__phase4_rogue_header">'
        printf '%s\n' '    SetHandler phase4-terminal-rogue'
        printf '%s\n' "$APACHE_LOCATION_END"
        if [ "$APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST" = "1" ] || \
            [ "$APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST" = "1" ]; then
            printf '%s\n' '<Location "/__phase4_fragmented_buckets">'
            printf '%s\n' '    SetHandler phase4-fragmented-bucket'
            printf '%s\n' "$APACHE_LOCATION_END"
            printf '%s\n' '<Location "/__phase4_fragmented_buckets_boundary">'
            printf '%s\n' '    SetHandler phase4-fragmented-bucket-boundary'
            printf '%s\n' "$APACHE_LOCATION_END"
        fi
        printf '%s\n' '<Location "/__phase4_internal_redirect">'
        printf '%s\n' '    SetHandler phase4-internal-redirect'
        printf '%s\n' "$APACHE_LOCATION_END"
        if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST" = "1" ]; then
            printf '%s\n' '<Location "/__phase4_internal_redirect_target_handler_test">'
            printf '%s\n' '    SetHandler phase4-internal-redirect-target-handler-test'
            printf '%s\n' "$APACHE_LOCATION_END"
            printf '%s\n' '<Location "/__phase4_internal_redirect_target_handler_target">'
            printf '%s\n' '    SetHandler phase4-internal-redirect-target-handler-marker'
            printf '%s\n' "$APACHE_LOCATION_END"
        fi
        printf '%s\n' '<Location "/__phase4_nested_error_document_redirect">'
        printf '%s\n' '    SetHandler phase4-nested-error-document-redirect'
        printf '%s\n' "$APACHE_LOCATION_END"
        printf '%s\n' '<Location "/__phase4_preoutput_error">'
        printf '%s\n' '    SetHandler phase4-preoutput-error-document'
        printf '%s\n' "$APACHE_LOCATION_END"
        if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST" = "1" ]; then
            printf '%s\n' '<Location "/__phase4_internal_redirect_target.txt">'
            printf '%s\n' '    modsecurity on'
            printf '    modsecurity_rules_file "%s"\n' \
                "$APACHE_PHASE4_REDIRECT_TARGET_RULES_FILE"
            printf '    modsecurity_phase4_log "%s"\n' \
                "$APACHE_PHASE4_LOG_FILE"
            printf '%s\n' "$APACHE_LOCATION_END"
        fi
        printf '%s\n' '<Location "/__phase4_downstream_error">'
        printf '%s\n' '    SetHandler phase4-downstream-error'
        printf '%s\n' "$APACHE_LOCATION_END"
        printf '%s\n' '<Location "/__phase4_upstream_error">'
        printf '%s\n' '    SetHandler phase4-upstream-error'
        printf '%s\n' "$APACHE_LOCATION_END"
    } >> "$APACHE_PHASE4_EXTRA_CONFIG"

    case "$APACHE_PHASE4_ROGUE_PROTOCOL" in
        http1) ;;
        h2)
            command -v "$OPENSSL_BIN" >/dev/null 2>&1 || \
                blocked "missing openssl for TLS H2 Phase-4 rogue test"
            "$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -days 1 \
                -subj '/CN=127.0.0.1' \
                -keyout "$PHASE4_ROGUE_TLS_KEY" \
                -out "$RUNTIME_ROOT/conf/phase4-rogue.crt" \
                > "$LOG_DIR/phase4-rogue-openssl.log" 2>&1 || \
                not_executable "could not create task-local TLS certificate for H2 rogue test"
            chmod 600 "$PHASE4_ROGUE_TLS_KEY" || \
                not_executable "could not restrict the task-local H2 private key"
            {
                printf '%s\n' 'Protocols h2 http/1.1'
                printf '%s\n' 'SSLEngine on'
                printf 'SSLCertificateFile "%s"\n' "$RUNTIME_ROOT/conf/phase4-rogue.crt"
                printf 'SSLCertificateKeyFile "%s"\n' "$PHASE4_ROGUE_TLS_KEY"
            } >> "$APACHE_PHASE4_EXTRA_CONFIG"
            ;;
        *) fail "unsupported APACHE_PHASE4_ROGUE_PROTOCOL=$APACHE_PHASE4_ROGUE_PROTOCOL" ;;
    esac
}

require_crs_preamble_if_needed() {
    if [ "$MODSECURITY_TEST_VARIANT" = "with-crs" ] && [ -z "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
        blocked "MODSECURITY_RULE_PREAMBLE_FILE is required for MODSECURITY_TEST_VARIANT=with-crs; run make test-with-crs or make prepare-crs"
    fi
}

resolve_apache_phase4_mode() {
    inherited_mode=${APACHE_PHASE4_MODE:-}
    resolved_mode=$("$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/harness-case-metadata.py" apache-phase4-mode \
        --case "$TEST_CASE" \
        --framework-root "$FRAMEWORK_ROOT" \
        --default safe \
        2>"$LOG_DIR/apache-phase4-mode.log") || \
        not_executable "failed to resolve Apache Phase-4 mode from case metadata; see $LOG_DIR/apache-phase4-mode.log"
    printf '%s\n' "$resolved_mode" >> "$LOG_DIR/apache-phase4-mode.log"
    case "$resolved_mode" in
        off|safe|strict) ;;
        *) not_executable "case metadata returned unsupported Apache Phase-4 mode: $resolved_mode" ;;
    esac
    if [ -n "$inherited_mode" ] && [ "$inherited_mode" != "$resolved_mode" ]; then
        fail "APACHE_PHASE4_MODE=$inherited_mode conflicts with case-resolved mode=$resolved_mode"
    fi
    APACHE_PHASE4_MODE=$resolved_mode
    export APACHE_PHASE4_MODE
}

require_crs_preamble_if_needed

if [ "$RUN_ONE_CASE" != "1" ]; then
    run_all_cases
fi

if [ -z "$TEST_CASE" ]; then
    TEST_CASE="phase2_args_block"
fi
TEST_CASE=$(resolve_case_path "$TEST_CASE") || exit 1
case_name=$(basename "$TEST_CASE" .yaml)
if [ -z "$RUNTIME_ROOT" ]; then
    RUNTIME_ROOT="$RUNTIME_BASE/$case_name"
fi
export MSCONNECTOR_APACHE_GUARD_ARTIFACT_ROOT="$RUNTIME_ROOT"
STATUS_FILE="$LOG_DIR/status.txt"

echo "apache_smoke: BUILD_ROOT=$BUILD_ROOT"
echo "apache_smoke: APACHE_BUILD_ROOT=$APACHE_BUILD_ROOT"
echo "apache_smoke: HTTPD_PREFIX=$HTTPD_PREFIX"
echo "apache_smoke: RUNTIME_ROOT=$RUNTIME_ROOT"
echo "apache_smoke: LOG_DIR=$LOG_DIR"
echo "apache_smoke: APACHE_MODULE=$APACHE_MODULE"
echo "apache_smoke: TEST_CASE=$TEST_CASE"
echo "apache_smoke: CASE_SCOPE=$CASE_SCOPE"
echo "apache_smoke: MODSECURITY_TEST_VARIANT=$MODSECURITY_TEST_VARIANT"
echo "apache_smoke: MSCONNECTOR_SMOKE_STAGE=$MSCONNECTOR_SMOKE_STAGE"
if [ -n "$MODSECURITY_RULE_PREAMBLE_FILE" ]; then
    echo "apache_smoke: MODSECURITY_RULE_PREAMBLE_FILE=$MODSECURITY_RULE_PREAMBLE_FILE"
fi

require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$APACHE_BUILD_ROOT" "APACHE_BUILD_ROOT"
require_absolute_generated_path "$HTTPD_PREFIX" "HTTPD_PREFIX"
require_absolute_generated_path "$RUNTIME_ROOT" "RUNTIME_ROOT"
require_absolute_generated_path "$LOG_DIR" "$APACHE_LOG_DIR_LABEL"
require_absolute_generated_path "$APACHE_CASE_OUTPUT_ROOT" "APACHE_CASE_OUTPUT_ROOT"
if [ "$RUN_ONE_CASE" = "1" ]; then
    require_absolute_generated_path "$RESULTS_DIR" "$APACHE_RESULTS_DIR_LABEL"
    if apache_profile_enabled; then
        [ -f "$APACHE_PROFILE_EVIDENCE_SCRIPT" ] || \
            blocked "Apache profile evidence helper is missing: $APACHE_PROFILE_EVIDENCE_SCRIPT"
        "$PYTHON_BIN" -P "$APACHE_PROFILE_EVIDENCE_SCRIPT" prepare-apache-selected-results \
            --runtime-root "$BUILD_ROOT" \
            --results-dir "$RESULTS_DIR" || \
            blocked "Apache profile results directory is unsafe"
    else
        prepare_runtime_directory "$RESULTS_DIR" "$APACHE_RESULTS_DIR_LABEL" 0
    fi
fi

RUNTIME_PID_FILE="$RUNTIME_ROOT/logs/httpd.pid"
HTTPD_SUPERVISOR_STATE="$RUNTIME_ROOT/run/httpd-supervisor-state.json"
HTTPD_SUPERVISOR_PID_OUTPUT="$RUNTIME_ROOT/run/httpd-supervisor.pid"

prepare_runtime_directory "$RUNTIME_ROOT" "RUNTIME_ROOT" 1
prepare_runtime_directory "$RUNTIME_ROOT/conf" "Apache runtime conf" 1
prepare_runtime_directory "$RUNTIME_ROOT/logs" "Apache runtime logs" 1
prepare_runtime_directory "$RUNTIME_ROOT/htdocs" "Apache runtime document root" 1
prepare_runtime_directory "$RUNTIME_ROOT/run" "Apache runtime state" 1
prepare_runtime_directory "$RUNTIME_ROOT/modules" "Apache runtime modules" 1
prepare_runtime_directory "$LOG_DIR/audit" "Apache audit logs" 1
[ ! -L "$RUNTIME_ROOT/run" ] || blocked "Apache runtime run directory must not be a symlink"
chmod 700 "$RUNTIME_ROOT/run"
if [ -e "$HTTPD_SUPERVISOR_STATE" ] || [ -L "$HTTPD_SUPERVISOR_STATE" ] || \
    [ -e "$HTTPD_SUPERVISOR_PID_OUTPUT" ] || [ -L "$HTTPD_SUPERVISOR_PID_OUTPUT" ]; then
    MSCONNECTOR_APACHE_GUARD_ARTIFACT_ROOT="$RUNTIME_ROOT" \
        "$PYTHON_BIN" "$APACHE_PROCESS_GUARD" retire-supervisor-artifact \
        --state "$HTTPD_SUPERVISOR_STATE" --pid-output "$HTTPD_SUPERVISOR_PID_OUTPUT" >/dev/null || \
        blocked "stale Apache supervisor session is unsafe"
fi
: > "$STATUS_FILE"
if [ -n "$APACHE_PROFILE_CLEANUP_RECEIPT" ] || [ -n "$APACHE_PROFILE_CELL_RUN_ID" ] || \
    [ -n "$APACHE_PROFILE_GITHUB_RUN_ID" ] || [ -n "$APACHE_PROFILE_GITHUB_RUN_ATTEMPT" ]; then
    apache_profile_enabled || blocked "Apache profile cleanup configuration is incomplete"
    [ "$RUN_ONE_CASE" = "1" ] || blocked "Apache profile cleanup requires one selected case"
    [ -f "$APACHE_PROFILE_EVIDENCE_SCRIPT" ] || \
        blocked "Apache profile evidence helper is missing: $APACHE_PROFILE_EVIDENCE_SCRIPT"
fi
stop_stale_runtime_pid "$RUNTIME_PID_FILE"
retire_stale_guard_evidence
rm -f "$RUNTIME_ROOT/logs/"* \
    "$LOG_DIR/configtest.log" \
    "$LOG_DIR/curl-attack.err" \
    "$LOG_DIR/curl-ready.err" \
    "$LOG_DIR/httpd.log" \
    "$LOG_DIR/access.log" \
    "$LOG_DIR/error.log" \
    "$LOG_DIR/phase4.log" \
    "$LOG_DIR/response-body.txt" \
    "$LOG_DIR/response-headers.txt" \
    "$LOG_DIR/audit.log"
rm -f "$LOG_DIR/audit/"*

APACHE_HTTPD_BIN=$(find_apache)
APXS_BIN=$(find_apxs)
case "$MSCONNECTOR_SMOKE_STAGE" in
    config_load|start_smoke|minimal_runtime_smoke) ;;
    *) fail "unsupported MSCONNECTOR_SMOKE_STAGE=$MSCONNECTOR_SMOKE_STAGE" ;;
esac

if [ "$MSCONNECTOR_SMOKE_STAGE" = "minimal_runtime_smoke" ]; then
    CURL_BIN=$(find_curl)
else
    CURL_BIN=
fi

[ -n "$APACHE_HTTPD_BIN" ] || blocked "missing Apache httpd executable; set APACHE_HTTPD=/path/to/apache2-or-httpd"
[ -x "$APACHE_HTTPD_BIN" ] || blocked "Apache executable is not executable: $APACHE_HTTPD_BIN"
[ -x "$(command -v "$SETSID_BIN" 2>/dev/null || true)" ] || \
    blocked "missing setsid required for isolated Apache cleanup session"
"$PYTHON_BIN" "$APACHE_PROCESS_GUARD" preflight >/dev/null || \
    blocked "Apache ownership guard/pidfd/proc preflight failed"
if [ "$MSCONNECTOR_SMOKE_STAGE" = "minimal_runtime_smoke" ]; then
    [ -n "$CURL_BIN" ] || blocked "missing curl; set CURL=/path/to/curl"
    [ -x "$CURL_BIN" ] || blocked "curl is not executable: $CURL_BIN"
fi
[ -f "$APACHE_MODULE" ] || blocked "missing Apache connector module: $APACHE_MODULE"

if [ ! -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ]; then
    if [ -f "$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so" ]; then
        MODSECURITY_LIB_DIR="$MODSECURITY_V3_DIR/src/.libs"
    else
        blocked "missing libmodsecurity.so in staged or build-copy library directories"
    fi
fi

MODULES_FILE="$RUNTIME_ROOT/conf/modules.load"
CONFIG_FILE="$RUNTIME_ROOT/conf/httpd.conf"
RULES_FILE="$RUNTIME_ROOT/conf/modsecurity-smoke.conf"
MIME_TYPES_FILE="$RUNTIME_ROOT/conf/mime.types"
MIME_TYPES_ROOT_FILE="$RUNTIME_ROOT/mime.types"
DOCROOT="$RUNTIME_ROOT/htdocs"
APACHE_BACKEND_PROXY_FILE="$RUNTIME_ROOT/conf/backend-proxy.conf"
RESPONSE_BODY="$LOG_DIR/response-body.txt"
RESPONSE_HEADERS="$LOG_DIR/response-headers.txt"
CASE_ENV_FILE="$RUNTIME_ROOT/conf/case.env"
REQUEST_HEADERS_FILE="$RUNTIME_ROOT/conf/request-headers.txt"
REQUEST_BODY_FILE="$RUNTIME_ROOT/conf/request-body.bin"
AUDIT_LOG_FILE="$LOG_DIR/audit.log"
AUDIT_LOG_DIR="$LOG_DIR/audit"
APACHE_PHASE4_LOG_FILE="$LOG_DIR/phase4.log"
RESPONSE_HEADER_FIXTURE_FILE="$RUNTIME_ROOT/conf/response-header-fixture.json"
APACHE_PHASE4_EXTRA_CONFIG="$RUNTIME_ROOT/conf/phase4-extra.conf"
PHASE4_ROGUE_OUTPUT="$RUNTIME_ROOT/modules/mod_phase4_terminal_rogue.so"
PHASE4_ROGUE_MODULE="$RUNTIME_ROOT/modules/.libs/mod_phase4_terminal_rogue.so"
PHASE4_ROGUE_SOURCE="$RUNTIME_ROOT/modules/mod_phase4_terminal_rogue.c"
PHASE4_ROGUE_RESPONSE_BODY="$LOG_DIR/phase4-rogue-response-body.txt"
PHASE4_ROGUE_ALLOW_BODY="$LOG_DIR/phase4-rogue-allow-body.txt"
PHASE4_ROGUE_TRANSFERS="$LOG_DIR/phase4-rogue-transfers.txt"
PHASE4_ROGUE_TRACE="$LOG_DIR/phase4-rogue-trace.txt"
PHASE4_ROGUE_TLS_KEY="$RUNTIME_ROOT/conf/phase4-rogue.key"
APACHE_PHASE4_REDIRECT_TARGET_RULES_FILE="$RUNTIME_ROOT/conf/phase4-redirect-target-rules.conf"

if [ -f "$HTTPD_PREFIX/conf/mime.types" ]; then
    cp -a "$HTTPD_PREFIX/conf/mime.types" "$MIME_TYPES_FILE"
    cp -a "$HTTPD_PREFIX/conf/mime.types" "$MIME_TYPES_ROOT_FILE"
else
    : > "$MIME_TYPES_FILE"
    : > "$MIME_TYPES_ROOT_FILE"
fi
set --
if [ -z "${APACHE_NATIVE_ORACLE_OVERRIDE:-}" ]; then
    set -- --native-profile apache-native
fi
if ! "$PYTHON_BIN" "$CASE_CLI" materialize "$@" \
    --case "$TEST_CASE" \
    --rules-file "$RULES_FILE" \
    --env-file "$CASE_ENV_FILE" \
    --headers-file "$REQUEST_HEADERS_FILE" \
    --body-file "$REQUEST_BODY_FILE" \
    --docroot "$DOCROOT" \
    --audit-log-file "$AUDIT_LOG_FILE" \
    --audit-log-dir "$AUDIT_LOG_DIR" \
    --output-root "$APACHE_CASE_OUTPUT_ROOT" \
    --rules-preamble-file "$MODSECURITY_RULE_PREAMBLE_FILE" > "$LOG_DIR/case-materialize.log" 2>&1; then
    not_executable "failed to materialize shared case; see $LOG_DIR/case-materialize.log"
fi
if [ -n "${APACHE_NATIVE_ORACLE_OVERRIDE:-}" ]; then
    [ -n "${APACHE_NATIVE_ORACLE_IDENTITY:-}" ] || \
        blocked "APACHE_NATIVE_ORACLE_IDENTITY is required for an explicit oracle override"
    "$PYTHON_BIN" "$SCRIPT_DIR/apache_oracle_overrides.py" \
        --selection "$APACHE_NATIVE_ORACLE_OVERRIDE" \
        --case "$TEST_CASE" --framework "$FRAMEWORK_ROOT" --rules "$RULES_FILE" \
        --identity "$APACHE_NATIVE_ORACLE_IDENTITY" \
        --receipt "$LOG_DIR/apache-native-oracle-override.json" || \
        blocked "Apache-native oracle override failed its source and proof guards"
fi
configure_apache_profile_audit
. "$CASE_ENV_FILE"
if ! "$PYTHON_BIN" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/harness-case-metadata.py" response-header-fixture \
    --case "$TEST_CASE" \
    --framework-root "$FRAMEWORK_ROOT" \
    --output "$RESPONSE_HEADER_FIXTURE_FILE" > "$LOG_DIR/response-header-fixture.log" 2>&1; then
    not_executable "failed to materialize response-header backend fixture; see $LOG_DIR/response-header-fixture.log"
fi
resolve_apache_phase4_mode
echo "apache_smoke: APACHE_PHASE4_MODE=$APACHE_PHASE4_MODE"
start_response_header_backend
write_backend_proxy_directives "$APACHE_BACKEND_PROXY_FILE"

: > "$MODULES_FILE"
if modules_dir=$(apache_modules_dir); then
    append_mpm_if_needed "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "authz_core_module" "mod_authz_core.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "authz_host_module" "mod_authz_host.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "unixd_module" "mod_unixd.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "dir_module" "mod_dir.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "mime_module" "mod_mime.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "proxy_module" "mod_proxy.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "proxy_http_module" "mod_proxy_http.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "log_config_module" "mod_log_config.so" "$modules_dir" "$MODULES_FILE"
    if phase4_terminal_test_uses_h2; then
        [ -f "$modules_dir/mod_socache_shmcb.so" ] || \
            blocked "Apache build has no mod_socache_shmcb required for TLS H2 rogue test"
        [ -f "$modules_dir/mod_ssl.so" ] || \
            blocked "Apache build has no mod_ssl required for TLS H2 rogue test"
        [ -f "$modules_dir/mod_http2.so" ] || \
            blocked "Apache build has no mod_http2 required for H2 rogue test"
        append_load_if_exists "socache_shmcb_module" "mod_socache_shmcb.so" "$modules_dir" "$MODULES_FILE"
        append_load_if_exists "ssl_module" "mod_ssl.so" "$modules_dir" "$MODULES_FILE"
        append_load_if_exists "http2_module" "mod_http2.so" "$modules_dir" "$MODULES_FILE"
    fi
fi
write_phase4_terminal_test_support

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR:$HTTPD_PREFIX/lib:$PCRE2_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH

trap on_exit EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
start_server

if [ "$MSCONNECTOR_SMOKE_STAGE" = "config_load" ]; then
    echo "apache_smoke: pass config_load (no process started, no request sent)"
    exit 0
fi
if [ "$MSCONNECTOR_SMOKE_STAGE" = "start_smoke" ]; then
    echo "apache_smoke: pass start_smoke (request-free host liveness verified)"
    exit 0
fi

if [ "$APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST" = "1" ]; then
    send_phase4_nested_error_document_redirect_request
    echo "apache_smoke: pass phase4-nested-error-document-redirect" >&2
    exit 0
fi

if [ "$APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST" = "1" ]; then
    send_phase4_preoutput_error_document_request
    echo "apache_smoke: pass phase4-preoutput-error-document" >&2
    exit 0
fi

if [ "$APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST" = "1" ]; then
    send_phase4_fragmented_buckets_request
    echo "apache_smoke: pass phase4-fragmented-buckets"
    exit 0
fi

if [ "$APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST" = "1" ]; then
    send_phase4_fragmented_bucket_boundary_request
    echo "apache_smoke: pass phase4-fragmented-buckets-boundary"
    exit 0
fi

if [ "$APACHE_PHASE4_ROGUE_TEST" = "1" ]; then
    send_phase4_rogue_request
    echo "apache_smoke: pass phase4-terminal-rogue"
    exit 0
fi

if [ "$APACHE_PHASE4_INTERNAL_REDIRECT_TEST" = "1" ]; then
    send_phase4_internal_redirect_request
    echo "apache_smoke: pass phase4-internal-redirect"
    exit 0
fi

if [ "$APACHE_PHASE4_DOWNSTREAM_ERROR_TEST" = "1" ]; then
    send_phase4_downstream_error_request
    echo "apache_smoke: pass phase4-downstream-error" >&2
    exit 0
fi

if [ "$APACHE_PHASE4_UPSTREAM_ERROR_TEST" = "1" ]; then
    send_phase4_upstream_error_request
    echo "apache_smoke: pass phase4-upstream-error" >&2
    exit 0
fi

if [ "$MSCONNECTOR_FULL_LIFECYCLE_SYNC" = "1" ]; then
    send_synchronized_first_byte_request
    echo "apache_smoke: pass synchronized-first-byte"
    exit 0
fi

set +e
http_status=$(send_case_request)
curl_rc=$?
set -e
observed_transport_result=$OBSERVED_TRANSPORT_HTTP_STATUS
if [ "$curl_rc" -ne 0 ]; then
    observed_transport_result=connection_aborted
fi
printf '%s\n' "$http_status" > "$LOG_DIR/observed-status.txt"
printf '%s\n' "$observed_transport_result" > "$LOG_DIR/observed-transport-result.txt"

if "$PYTHON_BIN" "$CASE_CLI" assert-status \
    --case "$TEST_CASE" \
    --actual-status "$http_status" \
    --observed-transport-result "$observed_transport_result" \
    --response-body-file "$RESPONSE_BODY" \
    --audit-log-file "$AUDIT_LOG_FILE" \
    --phase4-log-file "$APACHE_PHASE4_LOG_FILE" \
    --status-file "$STATUS_FILE" > "$LOG_DIR/case-assert.log" 2>&1; then
    if apache_profile_enabled; then
        "$PYTHON_BIN" -P "$APACHE_PROFILE_EVIDENCE_SCRIPT" verify-apache-audit \
            --audit-log "$AUDIT_LOG_FILE" || \
            fail "selected Apache CRS case lacks a transaction-bound rule-942270 audit record"
        APACHE_PROFILE_FINAL_CLEANUP=1
        if ! cleanup; then
            # A failed final proof must never publish a receipt.  Keep the
            # exit trap installed for one last best-effort teardown pass, but
            # disable final publication before this error path exits.
            APACHE_PROFILE_FINAL_CLEANUP=0
            fail "selected Apache CRS case cleanup could not be proven"
        fi
        trap - EXIT INT TERM
    fi
    if apache_profile_enabled; then
        write_case_result "$TEST_CASE" pass "$http_status" "$LOG_DIR/result.json" "$observed_transport_result" || \
            fail "selected Apache CRS case result publication failed"
        publish_profile_single_case_results
    else
        write_case_result "$TEST_CASE" pass "$http_status" "$LOG_DIR/result.json" "$observed_transport_result" || \
            fail "Apache case result publication failed"
    fi
    echo "apache_smoke: pass case=$CASE_NAME status=$http_status"
    exit 0
fi

reason=$(cat "$LOG_DIR/case-assert.log" 2>/dev/null || true)
if [ "$curl_rc" -ne 0 ]; then
    reason="curl attack request failed rc=$curl_rc; $reason"
fi
write_case_result "$TEST_CASE" fail "$http_status" "$LOG_DIR/result.json" "$observed_transport_result" "$reason" || \
    fail "Apache case result publication failed"
echo "apache_smoke: fail case=$CASE_NAME observed=$http_status expected=$EXPECT_STATUS"
exit 1
