#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
# Exercise the Apache/NGINX native module through a real reverse-proxy path
# while the Framework's upstream daemon is paused after its first chunk.
set -eu

connector=${1:?connector is required}
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
PYTHON=${PYTHON:-python3}
VERIFIED_RUN_ROOT=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}
BUILD_ROOT=${BUILD_ROOT:?BUILD_ROOT is required}
RESULTS_DIR=${RESULTS_DIR:?RESULTS_DIR is required}
HOST_RUNTIME_ROOT=${HOST_RUNTIME_ROOT:?HOST_RUNTIME_ROOT is required}
NO_CRS_RULES_FILE=${NO_CRS_RULES_FILE:?NO_CRS_RULES_FILE is required}
FULL_LIFECYCLE_EVIDENCE_OUTPUT=${FULL_LIFECYCLE_EVIDENCE_OUTPUT:?FULL_LIFECYCLE_EVIDENCE_OUTPUT is required}

case "$connector" in
    apache)
        harness=$TEST_ROOT/connector_suite/adapters/apache/harness/run_apache_smoke.sh
        port=${FULL_LIFECYCLE_APACHE_PORT:-19280}
        ;;
    nginx)
        harness=$TEST_ROOT/connector_suite/adapters/nginx/harness/run_nginx_smoke.sh
        port=${FULL_LIFECYCLE_NGINX_PORT:-19281}
        # This route invokes NGINX directly, so opt in here rather than
        # changing the direct-harness default used by local smoke commands.
        NGINX_DOCROOT_PROJECTION=1
        # The portable fixture deliberately has no host policy. Bind this
        # native Safe proof separately from its generated case environment.
        export NGINX_SYNCHRONIZED_PHASE4_MODE=safe
        export NGINX_PHASE4_LOG_SCOPE=server_with_location_override
        ;;
    *) echo "usage: $0 apache|nginx" >&2; exit 2 ;;
esac

[ -f "$harness" ] || { echo "BLOCKED: native harness is missing: $harness" >&2; exit 77; }
[ -f "$FRAMEWORK_ROOT/tests/runners/synchronized_upstream.py" ] || {
    echo "BLOCKED: synchronized upstream helper is missing" >&2
    exit 77
}

runtime_root=$HOST_RUNTIME_ROOT/first-byte-$connector
# First-byte result records retain the Phase-4 event path.  Keep that raw
# source beneath the connector run root so the canonical collector can verify
# containment and scrub it after normalization.  The parent canonical runner
# emits sanitized diagnostics separately after collection.
log_root=$HOST_RUNTIME_ROOT/$connector-first-byte-logs
results_output=$RESULTS_DIR/$connector-first-byte-results.jsonl
synchronized_control_root=${SYNCHRONIZED_UPSTREAM_CONTROL_ROOT:-$HOST_RUNTIME_ROOT/..}
if [ "$connector" = nginx ]; then
    # First-byte is an independent harness invocation, not another consumer
    # of a batch case's projection. Preserve authority and never pre-create it.
    "$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/validate-nginx-harness-paths.py" --quiet \
        --verified-run-root "$VERIFIED_RUN_ROOT" \
        --existing-private-directory NGINX_DOCROOT_PROJECTION_PARENT "${NGINX_DOCROOT_PROJECTION_PARENT:-}" \
        --existing-direct-child NGINX_DOCROOT_PROJECTION_ROOT "${NGINX_DOCROOT_PROJECTION_ROOT:-}" "${NGINX_DOCROOT_PROJECTION_PARENT:-}"
    NGINX_DOCROOT_PROJECTION_ROOT=$("$PYTHON" -c 'import pathlib, re, sys, uuid; seed = pathlib.Path(sys.argv[1]); re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", seed.name) or sys.exit("unsafe projection root name"); print(seed.with_name("nginx-first-byte-" + uuid.uuid4().hex))' "$NGINX_DOCROOT_PROJECTION_ROOT")
fi
mkdir -p "$RESULTS_DIR" "$runtime_root"

set +e
env \
RUNTIME_COMPONENT_TARGET=$connector \
CONNECTOR_ROOT="$CONNECTOR_ROOT" \
FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
BUILD_ROOT="$BUILD_ROOT" \
FULL_LIFECYCLE_EVIDENCE_OUTPUT="$FULL_LIFECYCLE_EVIDENCE_OUTPUT" \
SYNCHRONIZED_UPSTREAM_CONTROL_ROOT="$synchronized_control_root" \
NO_CRS_RULES_FILE="$NO_CRS_RULES_FILE" \
"$TEST_ROOT/connector_suite/modsecurity_connector_ci/provisioning/cache/with-runtime-components.sh" env \
    RUN_ONE_CASE=1 \
    TEST_CASE="$FRAMEWORK_ROOT/tests/cases/no-crs-baseline/full-lifecycle/phase4_first_byte_before_response_end.yaml" \
    CASE_SCOPE=all \
    MSCONNECTOR_SMOKE_STAGE=minimal_runtime_smoke \
    MSCONNECTOR_FULL_LIFECYCLE_SYNC=1 \
    NO_CRS_BASELINE=1 \
    MODSECURITY_TEST_VARIANT=no-crs \
    MODSECURITY_RULE_PREAMBLE_FILE="$NO_CRS_RULES_FILE" \
    RESULTS_DIR="$RESULTS_DIR" \
    RUNTIME_ROOT="$runtime_root" \
    RUNTIME_BASE="$HOST_RUNTIME_ROOT" \
    LOG_DIR="$log_root" \
    PORT="$port" \
    NGINX_HARNESS_PARENT="$HOST_RUNTIME_ROOT" \
    NGINX_HARNESS_WORK_ROOT="$HOST_RUNTIME_ROOT/nginx-harness" \
    NGINX_DOCROOT_PROJECTION="${NGINX_DOCROOT_PROJECTION:-0}" \
    NGINX_DOCROOT_PROJECTION_PARENT="${NGINX_DOCROOT_PROJECTION_PARENT:-}" \
    NGINX_DOCROOT_PROJECTION_ROOT="${NGINX_DOCROOT_PROJECTION_ROOT:-}" \
    "$harness"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    exit "$rc"
fi

phase4_log=$log_root/phase4.log
[ -s "$phase4_log" ] || {
    echo "FAIL: native first-byte run completed without a Phase-4 event: $phase4_log" >&2
    exit 1
}
[ -f "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" ] || {
    echo "FAIL: native first-byte run completed without barrier evidence" >&2
    exit 1
}
"$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-first-byte-source-results.py" \
    --connector "$connector" \
    --phase4-log "$phase4_log" \
    --first-byte-evidence "$FULL_LIFECYCLE_EVIDENCE_OUTPUT" \
    --output "$results_output"
printf 'native_first_byte_connector=%s\n' "$connector"
printf 'native_first_byte_phase4_log=%s\n' "$phase4_log"
printf 'native_first_byte_evidence=%s\n' "$FULL_LIFECYCLE_EVIDENCE_OUTPUT"
printf 'native_first_byte_results=%s\n' "$results_output"
