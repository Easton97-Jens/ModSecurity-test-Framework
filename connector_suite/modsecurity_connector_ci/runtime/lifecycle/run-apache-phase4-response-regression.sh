#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
# Exercise the Parent-owned Apache Phase-4 response gate without changing the
# Framework case catalog. The caller supplies a task-owned runtime environment.
set -eu

mode=${1:?usage: run-apache-phase4-response-regression.sh bypass|deny|allow|log-only|client-abort|empty|empty-deny|limit|custom-mime-deny|engine-limit|fragmented-buckets|fragmented-buckets-boundary|redirect-bypass-h1|redirect-abort-h1|redirect-bypass-h2|redirect-abort-h2|redirect-target-config-bypass-h1|redirect-target-config-abort-h1|redirect-uri-bypass-h1|redirect-uri-abort-h1|redirect-target-handler-abort-h1|redirect-target-handler-abort-h2|downstream-error-document-h1|downstream-error-document-h2|upstream-error-document-h1|upstream-error-document-h2|nested-error-document-redirect-h1|preoutput-error-document-h1|preoutput-error-document-h2|rogue-h1|rogue-allow-h1|rogue-p3-h1|rogue-p3-header-freeze-h1|rogue-p3-header-freeze-h2|rogue-error-document-h1|rogue-h2|rogue-error-document-h2}
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
HARNESS=$TEST_ROOT/connector_suite/adapters/apache/harness/run_apache_smoke.sh
CASE_ROOT=$SCRIPT_DIR/cases/apache-phase4-response

[ -f "$HARNESS" ] || { echo "BLOCKED: Apache harness is missing: $HARNESS" >&2; exit 77; }
[ -d "$CASE_ROOT" ] || { echo "BLOCKED: Parent regression cases are missing: $CASE_ROOT" >&2; exit 77; }
[ -d "$FRAMEWORK_ROOT" ] || { echo "BLOCKED: Framework checkout is missing: $FRAMEWORK_ROOT" >&2; exit 77; }

case "$mode" in
    bypass)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=bypass
        sync=1
        ;;
    deny)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=precommit_deny
        sync=1
        ;;
    allow)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=allow
        sync=1
        ;;
    log-only)
        case_file=$CASE_ROOT/log-only.yaml
        sync_expectation=log_only
        sync=1
        ;;
    client-abort)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=client_abort
        sync=1
        ;;
    empty)
        case_file=$CASE_ROOT/empty-allow.yaml
        sync_expectation=first_byte
        sync=0
        ;;
    empty-deny)
        case_file=$CASE_ROOT/empty-deny.yaml
        sync_expectation=first_byte
        sync=0
        ;;
    limit)
        case_file=$CASE_ROOT/limit-reject.yaml
        sync_expectation=first_byte
        sync=0
        ;;
    custom-mime-deny)
        case_file=$CASE_ROOT/custom-mime-deny.yaml
        sync_expectation=custom_mime_deny
        sync=1
        synchronized_upstream=$SCRIPT_DIR/apache_phase4_content_type_synchronized_upstream.py
        synchronized_upstream_control_root=1
        ;;
    engine-limit)
        case_file=$CASE_ROOT/engine-limit-process-partial.yaml
        sync_expectation=engine_append_failure
        sync=1
        ;;
    fragmented-buckets)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        fragmented_buckets_test=1
        ;;
    fragmented-buckets-boundary)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        fragmented_bucket_boundary_test=1
        ;;
    redirect-bypass-h1)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=bypass
        ;;
    redirect-abort-h1)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=abort
        ;;
    redirect-bypass-h2)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=bypass
        rogue_protocol=h2
        ;;
    redirect-abort-h2)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=abort
        rogue_protocol=h2
        ;;
    redirect-target-config-bypass-h1)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=target_config_bypass
        internal_redirect_target_config_test=1
        internal_redirect_direct_rule_id=2190410
        ;;
    redirect-target-config-abort-h1)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=target_config_abort
        internal_redirect_target_config_test=1
        internal_redirect_direct_rule_id=2190410
        ;;
    redirect-uri-bypass-h1)
        case_file=$CASE_ROOT/redirect-uri-policy.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=uri_policy_bypass
        internal_redirect_uri_policy_test=1
        internal_redirect_direct_rule_id=2190411
        ;;
    redirect-uri-abort-h1)
        case_file=$CASE_ROOT/redirect-uri-policy.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=uri_policy_abort
        internal_redirect_uri_policy_test=1
        internal_redirect_direct_rule_id=2190411
        ;;
    redirect-target-handler-abort-h1)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=target_handler_abort
        internal_redirect_target_handler_test=1
        ;;
    redirect-target-handler-abort-h2)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        internal_redirect_test=1
        internal_redirect_expect=target_handler_abort
        internal_redirect_target_handler_test=1
        rogue_protocol=h2
        ;;
    downstream-error-document-h1)
        case_file=$CASE_ROOT/log-only.yaml
        sync_expectation=first_byte
        sync=0
        downstream_error_test=1
        rogue_protocol=http1
        ;;
    downstream-error-document-h2)
        case_file=$CASE_ROOT/log-only.yaml
        sync_expectation=first_byte
        sync=0
        downstream_error_test=1
        rogue_protocol=h2
        ;;
    upstream-error-document-h1)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        upstream_error_test=1
        rogue_protocol=http1
        ;;
    upstream-error-document-h2)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        upstream_error_test=1
        rogue_protocol=h2
        ;;
    nested-error-document-redirect-h1)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        nested_error_redirect_test=1
        rogue_protocol=http1
        ;;
    preoutput-error-document-h1)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        preoutput_error_document_test=1
        rogue_protocol=http1
        ;;
    preoutput-error-document-h2)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        preoutput_error_document_test=1
        rogue_protocol=h2
        ;;
    rogue-h1)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=http1
        ;;
    rogue-allow-h1)
        case_file=$CASE_ROOT/allow.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=http1
        rogue_expect=allow
        ;;
    rogue-p3-h1)
        case_file=$CASE_ROOT/precommit-phase3-deny.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=http1
        rogue_phase=p3
        ;;
    rogue-p3-header-freeze-h1)
        case_file=$CASE_ROOT/precommit-phase3-header-freeze.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=http1
        rogue_expect=allow
        rogue_phase=p3
        rogue_header_mutation=1
        ;;
    rogue-p3-header-freeze-h2)
        case_file=$CASE_ROOT/precommit-phase3-header-freeze.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=h2
        rogue_expect=allow
        rogue_phase=p3
        rogue_header_mutation=1
        ;;
    rogue-error-document-h1)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=http1
        error_document=1
        ;;
    rogue-h2)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=h2
        ;;
    rogue-error-document-h2)
        case_file=$CASE_ROOT/precommit-deny.yaml
        sync_expectation=first_byte
        sync=0
        rogue_test=1
        rogue_protocol=h2
        error_document=1
        ;;
    *)
        echo "usage: run-apache-phase4-response-regression.sh bypass|deny|allow|log-only|client-abort|empty|empty-deny|limit|custom-mime-deny|engine-limit|fragmented-buckets|fragmented-buckets-boundary|redirect-bypass-h1|redirect-abort-h1|redirect-bypass-h2|redirect-abort-h2|redirect-target-config-bypass-h1|redirect-target-config-abort-h1|redirect-uri-bypass-h1|redirect-uri-abort-h1|redirect-target-handler-abort-h1|redirect-target-handler-abort-h2|downstream-error-document-h1|downstream-error-document-h2|upstream-error-document-h1|upstream-error-document-h2|nested-error-document-redirect-h1|preoutput-error-document-h1|preoutput-error-document-h2|rogue-h1|rogue-allow-h1|rogue-p3-h1|rogue-p3-header-freeze-h1|rogue-p3-header-freeze-h2|rogue-error-document-h1|rogue-h2|rogue-error-document-h2" >&2
        exit 2
        ;;
esac

[ -f "$case_file" ] || { echo "BLOCKED: Parent regression case is missing: $case_file" >&2; exit 77; }
: "${BUILD_ROOT:?BUILD_ROOT is required}"
: "${RUNTIME_ROOT:?RUNTIME_ROOT is required}"
: "${LOG_DIR:?LOG_DIR is required}"
: "${PORT:?PORT is required}"

case "${EXTRA_CASE_ROOTS:-}" in
    "") EXTRA_CASE_ROOTS=$CASE_ROOT ;;
    *) EXTRA_CASE_ROOTS=$EXTRA_CASE_ROOTS:$CASE_ROOT ;;
esac
export EXTRA_CASE_ROOTS

MODSECURITY_RULE_PREAMBLE_FILE=
export MODSECURITY_RULE_PREAMBLE_FILE

exec env \
    FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
    RUN_ONE_CASE=1 \
    FORCE_ALL_CASES=1 \
    TEST_CASE="$case_file" \
    CASE_SCOPE=all \
    MSCONNECTOR_SMOKE_STAGE=minimal_runtime_smoke \
    MSCONNECTOR_FULL_LIFECYCLE_SYNC="$sync" \
    MSCONNECTOR_PHASE4_SYNC_EXPECTATION="$sync_expectation" \
    SYNCHRONIZED_UPSTREAM="${synchronized_upstream:-}" \
    APACHE_PHASE4_SYNCHRONIZED_UPSTREAM_CONTROL_ROOT="${synchronized_upstream_control_root:-0}" \
    APACHE_PHASE4_SYNC_CONTENT_TYPE="${APACHE_PHASE4_SYNC_CONTENT_TYPE:-application/vnd.apache-phase4+json}" \
    APACHE_PHASE4_FRAGMENTED_BUCKETS_TEST="${fragmented_buckets_test:-0}" \
    APACHE_PHASE4_FRAGMENTED_BUCKET_BOUNDARY_TEST="${fragmented_bucket_boundary_test:-0}" \
    APACHE_PHASE4_ROGUE_TEST="${rogue_test:-0}" \
    APACHE_PHASE4_ROGUE_PROTOCOL="${rogue_protocol:-http1}" \
    APACHE_PHASE4_ERROR_DOCUMENT="${error_document:-0}" \
    APACHE_PHASE4_ROGUE_EXPECT="${rogue_expect:-deny}" \
    APACHE_PHASE4_ROGUE_PHASE="${rogue_phase:-p4}" \
    APACHE_PHASE4_ROGUE_HEADER_MUTATION="${rogue_header_mutation:-0}" \
    APACHE_PHASE4_INTERNAL_REDIRECT_TEST="${internal_redirect_test:-0}" \
    APACHE_PHASE4_INTERNAL_REDIRECT_EXPECT="${internal_redirect_expect:-abort}" \
    APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_CONFIG_TEST="${internal_redirect_target_config_test:-0}" \
    APACHE_PHASE4_INTERNAL_REDIRECT_URI_POLICY_TEST="${internal_redirect_uri_policy_test:-0}" \
    APACHE_PHASE4_INTERNAL_REDIRECT_TARGET_HANDLER_TEST="${internal_redirect_target_handler_test:-0}" \
    APACHE_PHASE4_INTERNAL_REDIRECT_DIRECT_RULE_ID="${internal_redirect_direct_rule_id:-}" \
    APACHE_PHASE4_DOWNSTREAM_ERROR_TEST="${downstream_error_test:-0}" \
    APACHE_PHASE4_UPSTREAM_ERROR_TEST="${upstream_error_test:-0}" \
    APACHE_PHASE4_NESTED_ERROR_REDIRECT_TEST="${nested_error_redirect_test:-0}" \
    APACHE_PHASE4_PREOUTPUT_ERROR_DOCUMENT_TEST="${preoutput_error_document_test:-0}" \
    NO_CRS_BASELINE=0 \
    MODSECURITY_TEST_VARIANT=no-crs \
  sh "$HARNESS"
