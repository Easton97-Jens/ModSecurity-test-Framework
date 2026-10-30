#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

CONNECTOR_NAME=${1:?connector name is required}
INTEGRATION_MODE=${2:?integration mode is required}
BINARY_ENV_VAR=${3:?runtime binary environment variable is required}
BINARY_NAME=${4:?runtime binary name is required}
MISSING_BINARY_REASON=${5:?missing binary skipped reason is required}
POST_LOOKUP_BLOCKED_REASON=${6:?post lookup skipped reason is required}
POST_LOOKUP_MISSING_DEPENDENCY=${7:?post lookup missing dependency is required}
ARCHITECTURE_DECISION=${8:-}
INTEGRATION_MODE_SELECTED=${9:-1}

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
DEFAULT_CONNECTOR_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd)
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$DEFAULT_CONNECTOR_ROOT}"
CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$CONNECTOR_ROOT/modules/ModSecurity-test-Framework}"
CONNECTOR_DIR="$CONNECTOR_ROOT/connectors/$CONNECTOR_NAME"
HARNESS_PATH="${HARNESS_PATH:-$CONNECTOR_DIR/harness/run_${CONNECTOR_NAME}_smoke.sh}"
CONNECTOR_SMOKE_SCRIPT_DIR="$FRAMEWORK_ROOT/ci"

export CONNECTOR_ROOT FRAMEWORK_ROOT HARNESS_PATH CONNECTOR_SMOKE_SCRIPT_DIR

. "$FRAMEWORK_ROOT/ci/lib/connector-smoke-common.sh"

[ -d "$CONNECTOR_DIR" ] || connector_skip_missing_dependency \
    "$CONNECTOR_NAME" \
    "$INTEGRATION_MODE" \
    "connector directory missing" \
    "$CONNECTOR_NAME" \
    "$ARCHITECTURE_DECISION" \
    "" \
    "$BINARY_ENV_VAR" \
    "$BINARY_NAME"

runtime_binary=""
runtime_missing_dependency=""
if runtime_binary=$(find_runtime_binary "$BINARY_ENV_VAR" "$BINARY_NAME"); then
    :
else
    runtime_missing_dependency="$BINARY_NAME"
fi

if [ "$INTEGRATION_MODE_SELECTED" != "1" ]; then
    if [ -z "$runtime_missing_dependency" ]; then
        runtime_missing_dependency="$POST_LOOKUP_MISSING_DEPENDENCY"
    fi
    connector_skip_missing_dependency \
        "$CONNECTOR_NAME" \
        "$INTEGRATION_MODE" \
        "$POST_LOOKUP_BLOCKED_REASON" \
        "$runtime_missing_dependency" \
        "$ARCHITECTURE_DECISION" \
        "$runtime_binary" \
        "$BINARY_ENV_VAR" \
        "$BINARY_NAME"
fi

if [ -z "$runtime_binary" ]; then
    connector_skip_missing_dependency \
        "$CONNECTOR_NAME" \
        "$INTEGRATION_MODE" \
        "$MISSING_BINARY_REASON" \
        "$BINARY_NAME" \
        "$ARCHITECTURE_DECISION" \
        "" \
        "$BINARY_ENV_VAR" \
        "$BINARY_NAME"
fi

decision_backend_raw=$(connector_smoke_decision_backend_value "$CONNECTOR_NAME")
if decision_backend=$(connector_smoke_normalize_decision_backend "$decision_backend_raw"); then
    :
else
    connector_skip_missing_dependency \
        "$CONNECTOR_NAME" \
        "$INTEGRATION_MODE" \
        "unsupported decision backend: $decision_backend_raw" \
        "decision backend" \
        "$ARCHITECTURE_DECISION" \
        "$runtime_binary" \
        "$BINARY_ENV_VAR" \
        "$BINARY_NAME"
fi

modsecurity_rule_file=$(connector_smoke_modsecurity_rule_file)
if [ "$decision_backend" = "libmodsecurity" ]; then
    if connector_smoke_resolve_modsecurity_backend "$modsecurity_rule_file"; then
        :
    else
        connector_skip_missing_dependency \
            "$CONNECTOR_NAME" \
            "$INTEGRATION_MODE" \
            "${CONNECTOR_SMOKE_MODSECURITY_MISSING_REASON:-libmodsecurity runtime dependency not available in local common.sh-managed paths}" \
            "${CONNECTOR_SMOKE_MODSECURITY_MISSING_DEPENDENCY:-libmodsecurity}" \
            "$ARCHITECTURE_DECISION" \
            "$runtime_binary" \
            "$BINARY_ENV_VAR" \
            "$BINARY_NAME"
    fi
fi

case "$CONNECTOR_NAME" in
    envoy|traefik|lighttpd)
        runner="$TEST_ROOT/connector_suite/common/scripts/run_local_runtime_smoke.py"
        [ -f "$runner" ] || connector_skip_missing_dependency \
            "$CONNECTOR_NAME" \
            "$INTEGRATION_MODE" \
            "local runtime smoke runner missing" \
            "local runtime smoke runner" \
            "$ARCHITECTURE_DECISION" \
            "$runtime_binary" \
            "$BINARY_ENV_VAR" \
            "$BINARY_NAME"

        evidence_root=$(resolve_evidence_root "$CONNECTOR_NAME")
        log_dir=$(resolve_log_root "$CONNECTOR_NAME" "$evidence_root")
        case "$CONNECTOR_NAME" in
            envoy)
                config_root="${ENVOY_CONFIG_ROOT:-$evidence_root/config}"
                smoke_port="${ENVOY_SMOKE_PORT:-0}"
                upstream_port="${ENVOY_UPSTREAM_PORT:-0}"
                authz_port="${ENVOY_AUTHZ_PORT:-0}"
                ;;
            traefik)
                config_root="${TRAEFIK_CONFIG_ROOT:-$evidence_root/config}"
                smoke_port="${TRAEFIK_SMOKE_PORT:-0}"
                upstream_port="${TRAEFIK_UPSTREAM_PORT:-0}"
                authz_port="${TRAEFIK_AUTHZ_PORT:-0}"
                ;;
            lighttpd)
                config_root="${LIGHTTPD_CONFIG_ROOT:-$evidence_root/config}"
                smoke_port="${LIGHTTPD_SMOKE_PORT:-0}"
                upstream_port="${LIGHTTPD_UPSTREAM_PORT:-0}"
                authz_port="${LIGHTTPD_AUTHZ_PORT:-0}"
                ;;
            *)
                connector_skip_missing_dependency \
                    "$CONNECTOR_NAME" \
                    "$INTEGRATION_MODE" \
                    "$POST_LOOKUP_BLOCKED_REASON" \
                    "$POST_LOOKUP_MISSING_DEPENDENCY" \
                    "$ARCHITECTURE_DECISION" \
                    "$runtime_binary" \
                    "$BINARY_ENV_VAR" \
                    "$BINARY_NAME"
                ;;
        esac
        ensure_runtime_dirs "$evidence_root"
        connector_smoke_require_runtime_path "$config_root" CONFIG_ROOT
        connector_smoke_require_runtime_path "$log_dir" LOG_DIR
        mkdir -p "$config_root" "$log_dir"
        lookup_args=$(connector_smoke_runtime_lookup_roots_args "$CONNECTOR_NAME")

        # shellcheck disable=SC2086
        "$PYTHON_BIN" "$runner" \
            --connector "$CONNECTOR_NAME" \
            --integration-mode "$INTEGRATION_MODE" \
            --resolved-runtime-binary "$runtime_binary" \
            --runtime-binary-env-var "$BINARY_ENV_VAR" \
            --runtime-binary-name "$BINARY_NAME" \
            --evidence-root "$evidence_root" \
            --results-dir "$RESULTS_DIR" \
            --connector-root "$CONNECTOR_ROOT" \
            --source-root "$SOURCE_ROOT" \
            --build-root "$BUILD_ROOT" \
            --tmp-root "$TMP_ROOT" \
            --log-root "$LOG_ROOT" \
            --log-dir "$log_dir" \
            --config-root "$config_root" \
            --listen-port "$smoke_port" \
            --upstream-port "$upstream_port" \
            --authz-port "$authz_port" \
            --harness-path "$HARNESS_PATH" \
            --architecture-decision "$ARCHITECTURE_DECISION" \
            --decision-backend "$decision_backend" \
            --modsecurity-ruleset "${MODSECURITY_RULESET:-targeted}" \
            --modsecurity-smoke-case "${MODSECURITY_SMOKE_CASE:-targeted}" \
            --crs-smoke-case "${CRS_SMOKE_CASE:-minimal}" \
            --modsecurity-rule-file "$modsecurity_rule_file" \
            --modsecurity-include-dir "${MODSECURITY_INCLUDE_DIR:-}" \
            --modsecurity-lib-dir "${MODSECURITY_LIB_DIR:-}" \
            --modsecurity-lib-file "${MODSECURITY_LIB_FILE:-}" \
            --modsecurity-pkg-config-path "${MODSECURITY_PKG_CONFIG_PATH:-}" \
            --modsecurity-prefix "${MODSECURITY_PREFIX:-}" \
            --modsecurity-manifest "${MODSECURITY_MANIFEST:-}" \
            --crs-repo-url "${CRS_REPO_URL:-}" \
            --crs-git-ref "${CRS_GIT_REF:-}" \
            --crs-source-dir "${CRS_SOURCE_DIR:-}" \
            --crs-runtime-dir "${CRS_RUNTIME_DIR:-}" \
            $lookup_args
        exit $?
        ;;
    *)
        connector_skip_missing_dependency \
            "$CONNECTOR_NAME" \
            "$INTEGRATION_MODE" \
            "$POST_LOOKUP_BLOCKED_REASON" \
            "$POST_LOOKUP_MISSING_DEPENDENCY" \
            "$ARCHITECTURE_DECISION" \
            "$runtime_binary" \
            "$BINARY_ENV_VAR" \
            "$BINARY_NAME"
        ;;
esac

connector_skip_missing_dependency \
    "$CONNECTOR_NAME" \
    "$INTEGRATION_MODE" \
    "$POST_LOOKUP_BLOCKED_REASON" \
    "$POST_LOOKUP_MISSING_DEPENDENCY" \
    "$ARCHITECTURE_DECISION" \
    "$runtime_binary" \
    "$BINARY_ENV_VAR" \
    "$BINARY_NAME"
