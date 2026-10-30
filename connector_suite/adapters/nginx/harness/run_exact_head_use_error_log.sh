#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu
PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite"
export PYTHONPATH

# This exact-head gate is the scoped GitHub-hosted functional-A integration
# test. It is not an independent attestation against hostile candidate-
# controlled VM-root code; the protected broker/attestation path is separate.
SCRIPT_DIR=$(CDPATH= cd -- "$(/usr/bin/dirname "$0")" && /bin/pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${FRAMEWORK_ROOT:?FRAMEWORK_ROOT is required explicitly}
[ "$FRAMEWORK_ROOT" = "$TEST_ROOT" ] || { echo "FAIL: Framework source roots differ" >&2; exit 1; }
FUNCTIONAL_ROOT=${NGINX_FUNCTIONAL_A_ROOT:-}
FUNCTIONAL_PARENT_ROOT=${NGINX_FUNCTIONAL_A_PARENT_ROOT:-}
RULE_PREAMBLE=${MODSECURITY_RULE_PREAMBLE_FILE:-$FRAMEWORK_ROOT/tests/rules/no-crs-baseline.conf}
FUNCTIONAL_RUNTIME_LIBRARY=${NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY:-}
FUNCTIONAL_EVIDENCE_ROOT=${NGINX_FUNCTIONAL_A_EVIDENCE_ROOT:-}
FUNCTIONAL_EVIDENCE_OWNER_UID=${NGINX_FUNCTIONAL_A_EVIDENCE_OWNER_UID:-}
FUNCTIONAL_EVIDENCE_OWNER_GID=${NGINX_FUNCTIONAL_A_EVIDENCE_OWNER_GID:-}
EXPECTED_PARENT_SHA=${EXPECTED_PARENT_SHA:-}
NGINX_ARCHIVE_SHA256=${NGINX_SHA256:-}
PHASE4_CASE=nginx_phase4_deny_after_commit_log_only
INHERITANCE_CASE=phase1_header_block
ALLOW_CASE=allow_without_marker
FUNCTIONAL_SCOPE=${NGINX_FUNCTIONAL_SCOPE:-selected-phase4}
case "$FUNCTIONAL_SCOPE" in selected-phase4|full) ;; *) echo "FAIL: unknown Functional-A selection scope" >&2; exit 2 ;; esac
if [ "$FUNCTIONAL_SCOPE" = full ] && [ "${ON_DEMAND_TESTS:-0}" != 1 ]; then
    echo "FAIL: full Functional-A campaign requires explicit ON_DEMAND_TESTS=1" >&2
    exit 2
fi

fail() {
    echo "nginx_exact_head: fail $*" >&2
    exit 1
}

blocked() {
    echo "nginx_exact_head: blocked $*" >&2
    exit 77
}

require_fresh_private_directory() {
    directory=$1
    [ -n "$directory" ] || fail "empty private directory"
    case "$directory" in
        /*) ;;
        *) fail "private directory is not absolute: $directory" ;;
    esac
    [ ! -e "$directory" ] && [ ! -L "$directory" ] || \
        fail "private directory is unexpectedly occupied: $directory"
    /bin/mkdir "$directory" || fail "could not create private directory: $directory"
    /bin/chown root:root "$directory" || fail "could not own private directory: $directory"
    /bin/chmod 700 "$directory" || fail "could not lock private directory: $directory"
}

require_fresh_worker_traversable_directory() {
    directory=$1
    require_fresh_private_directory "$directory"
    [ "$(/usr/bin/stat -c '%u:%a' -- "$directory")" = "0:700" ] || \
        fail "fresh worker ancestor did not retain root-owned private setup: $directory"
    /bin/chmod 711 "$directory" || \
        fail "could not make worker ancestor non-enumerably traversable: $directory"
    [ "$(/usr/bin/stat -c '%u:%a' -- "$directory")" = "0:711" ] || \
        fail "worker ancestor does not have exact root-owned mode 0711: $directory"
}

require_existing_non_symlink_directory() {
    directory=$1
    [ -n "$directory" ] || blocked "empty existing directory"
    case "$directory" in
        /*) ;;
        *) blocked "existing directory is not absolute: $directory" ;;
    esac
    [ -d "$directory" ] && [ ! -L "$directory" ] || \
        blocked "existing directory is unavailable or a symlink: $directory"
    resolved_directory=$(/usr/bin/readlink -f -- "$directory") || \
        blocked "could not canonicalize existing directory: $directory"
    [ "$resolved_directory" = "$directory" ] || \
        blocked "existing directory resolves through a symlink: $directory"
}

require_existing_non_symlink_regular_file() {
    file=$1
    [ -n "$file" ] || blocked "empty existing regular file"
    case "$file" in
        /*) ;;
        *) blocked "existing regular file is not absolute: $file" ;;
    esac
    [ -f "$file" ] && [ ! -L "$file" ] || \
        blocked "existing regular file is unavailable or a symlink: $file"
    resolved_file=$(/usr/bin/readlink -f -- "$file") || \
        blocked "could not canonicalize existing regular file: $file"
    [ "$resolved_file" = "$file" ] || \
        blocked "existing regular file resolves through a symlink: $file"
}

write_artifact_identity() {
    identity_output=$1
    /usr/bin/sha256sum -- \
        "$NGINX_BINARY" \
        "$NGINX_MODULE" \
        "$FUNCTIONAL_RUNTIME_LIBRARY" \
        "$RULE_PREAMBLE" \
        "$FRAMEWORK_ROOT/tests/cases/connector-specific/nginx/nginx_phase4_deny_after_commit_log_only.yaml" \
        "$FRAMEWORK_ROOT/tests/cases/request/headers/phase1_header_block.yaml" \
        "$FRAMEWORK_ROOT/tests/cases/no-crs-baseline/allow_without_marker.yaml" \
        > "$identity_output" || fail "could not hash the functional-A artifact set"
    /bin/chmod 600 "$identity_output"
}

assert_same_artifact_identity() {
    expected=$1
    observed=$2
    /usr/bin/cmp -s "$expected" "$observed" || \
        fail "candidate binary/module/rules artifact identity changed: $observed"
}

require_functional_evidence_stage() {
    case "$FUNCTIONAL_EVIDENCE_OWNER_UID:$FUNCTIONAL_EVIDENCE_OWNER_GID" in
        *[!0-9:]*|:*) fail "invalid Functional-A evidence owner" ;;
        *) ;;
    esac
    case "$EXPECTED_PARENT_SHA" in
        ''|*[!0123456789abcdef]*) fail "invalid expected Parent head for Functional-A evidence" ;;
        *) ;;
    esac
    case "$NGINX_ARCHIVE_SHA256" in
        ''|*[!0123456789abcdef]*) fail "invalid NGINX archive SHA-256 for Functional-A evidence" ;;
        *) ;;
    esac
    [ "${#EXPECTED_PARENT_SHA}" -eq 40 ] || \
        fail "expected Parent head is not an exact commit SHA for Functional-A evidence"
    [ "${#NGINX_ARCHIVE_SHA256}" -eq 64 ] || \
        fail "NGINX archive digest is not an exact SHA-256 for Functional-A evidence"
    require_existing_non_symlink_directory "$FUNCTIONAL_EVIDENCE_ROOT"
    [ "$(/usr/bin/stat -c '%u:%g:%a' -- "$FUNCTIONAL_EVIDENCE_ROOT")" = \
        "$FUNCTIONAL_EVIDENCE_OWNER_UID:$FUNCTIONAL_EVIDENCE_OWNER_GID:700" ] || \
        fail "Functional-A evidence stage is not the private runner-owned directory"
}

publish_functional_evidence() {
    require_functional_evidence_stage
    functional_evidence_writer="$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-nginx-functional-a-evidence.py"
    [ -f "$functional_evidence_writer" ] && [ ! -L "$functional_evidence_writer" ] || \
        fail "missing bounded Functional-A evidence writer"
    /usr/bin/python3 -I "$functional_evidence_writer" \
        --connector-root "$CONNECTOR_ROOT" \
        --functional-root "$FUNCTIONAL_ROOT" \
        --evidence-root "$FUNCTIONAL_EVIDENCE_ROOT" \
        --owner-uid "$FUNCTIONAL_EVIDENCE_OWNER_UID" \
        --owner-gid "$FUNCTIONAL_EVIDENCE_OWNER_GID" \
        --parent-sha "$EXPECTED_PARENT_SHA" \
        --nginx-archive-sha256 "$NGINX_ARCHIVE_SHA256" --scope "$FUNCTIONAL_SCOPE" || \
        fail "could not publish bounded Functional-A evidence"
}

run_harness_case() {
    mode_root=$1
    case_label=$2
    test_case=$3
    target_mode=$4
    log_scope=$5
    lifecycle_probe=$6
    query_canary=$7
    case_root="$mode_root/$case_label"
    require_fresh_worker_traversable_directory "$case_root"

    NGINX_USE_ERROR_LOG="$CURRENT_MODE" \
    VERIFIED_RUN_ROOT="$mode_root" \
    VERIFIED_BUILD_ROOT="$case_root" \
    BUILD_ROOT="$case_root" \
    LOG_ROOT="$case_root/logs" \
    RESULTS_DIR="$case_root/results" \
    NGINX_HARNESS_PARENT="$case_root/harness-parent" \
    NGINX_HARNESS_WORK_ROOT="$case_root/harness" \
    RUNTIME_BASE="$case_root/runtime-base" \
    RUNTIME_ROOT="$case_root/runtime" \
    LOG_DIR="$case_root/logs" \
    MODSECURITY_TEST_VARIANT=no-crs \
    NO_CRS_BASELINE=1 \
    MODSECURITY_RULE_PREAMBLE_FILE="$RULE_PREAMBLE" \
    FORCE_ALL_CASES=1 \
    TEST_CASE="$test_case" \
    RUN_ONE_CASE=1 \
    CASE_SCOPE=all \
    NGINX_PHASE4_LOG_TARGET_MODE="$target_mode" \
    NGINX_PHASE4_LOG_SCOPE="$log_scope" \
    NGINX_PHASE4_LOG_LIFECYCLE_PROBE="$lifecycle_probe" \
    NGINX_FUNCTIONAL_A_QUERY_CANARY="$query_canary" \
    NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY="$FUNCTIONAL_RUNTIME_LIBRARY" \
    /bin/sh "$SCRIPT_DIR/run_nginx_smoke.sh"
}

expect_config_rejection() {
    mode_root=$1
    target_mode=$2
    label="config-reject-$target_mode"
    set +e
    run_harness_case "$mode_root" "$label" "$PHASE4_CASE" "$target_mode" location 0 0
    rejection_rc=$?
    set -e
    [ "$rejection_rc" -eq 1 ] || \
        fail "unsafe phase4 target $target_mode returned $rejection_rc instead of a config failure"
    config_log="$mode_root/$label/logs/configtest.log"
    [ -f "$config_log" ] || fail "unsafe phase4 target $target_mode has no configtest log"
    /usr/bin/grep -F 'modsecurity_phase4_log' "$config_log" >/dev/null || \
        fail "unsafe phase4 target $target_mode did not reach the native directive parser"
}

assert_phase4_jsonl_and_callback() {
    mode_root=$1
    case_root="$mode_root/phase4"
    current_log="$case_root/logs/phase4.log"
    prior_log="$case_root/logs/phase4-before-usr1.log"
    error_log="$case_root/harness/server-logs/nginx_phase4_deny_after_commit_log_only/error.log"
    access_log="$case_root/harness/server-logs/nginx_phase4_deny_after_commit_log_only/access.log"
    lifecycle_log="$case_root/logs/nginx-lifecycle.txt"
    [ -f "$current_log" ] || fail "phase4 JSONL evidence is incomplete for mode=$CURRENT_MODE"
    if [ "$FUNCTIONAL_SCOPE" = full ]; then
        [ -f "$prior_log" ] || fail "USR1 JSONL evidence is incomplete for mode=$CURRENT_MODE"
    else
        prior_log=
    fi
    [ -f "$error_log" ] || fail "no deterministic NGINX error log for mode=$CURRENT_MODE"
    [ -f "$access_log" ] || fail "no deterministic NGINX access log for mode=$CURRENT_MODE"
    if [ "$FUNCTIONAL_SCOPE" = full ]; then
        [ -f "$lifecycle_log" ] || fail "no lifecycle evidence for mode=$CURRENT_MODE"
    fi

    /usr/bin/python3 - "$CURRENT_MODE" "$current_log" "$prior_log" "$error_log" "$access_log" <<'PY'
import json
import sys
from pathlib import Path

mode, current_name, prior_name, error_name, access_name = sys.argv[1:]
canary = "nginx-functional-a-canary=must-redact"
records = []
for name in (prior_name, current_name):
    if not name:
        continue
    raw = Path(name).read_text(encoding="utf-8")
    if canary in raw:
        raise SystemExit("query canary leaked into JSONL")
    for line in raw.splitlines():
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"invalid JSONL record: {error}") from error
        if not isinstance(record, dict):
            raise SystemExit("JSONL record is not an object")
        records.append(record)
if not records:
    raise SystemExit("no JSONL records")
phase4 = [record for record in records if str(record.get("rule_id")) == "1100301"]
if not phase4:
    raise SystemExit("phase4 rule 1100301 has no native JSONL record")
for record in phase4:
    if record.get("redacted") is not True:
        raise SystemExit("query-bearing native event is not marked redacted")
    if record.get("truncated") is not False:
        raise SystemExit("short query-bearing native event is unexpectedly truncated")
    if not isinstance(record.get("transaction_id"), str) or not record["transaction_id"]:
        raise SystemExit("native event lacks a transaction association")
    if record.get("uri") != "/no-crs/response-body?<redacted>":
        raise SystemExit(f"unexpected redacted URI: {record.get('uri')!r}")
    for field in ("sequence", "previous_event_hash", "event_hash"):
        value = record.get(field)
        if not isinstance(value, int) or value < 0:
            raise SystemExit(f"native event integrity field is invalid: {field}")
error_log = Path(error_name).read_text(encoding="utf-8")
if mode == "on":
    if "1100301" not in error_log:
        raise SystemExit("native callback marker absent with error-log on")
else:
    if "1100301" in error_log:
        raise SystemExit("native callback marker leaked with error-log off")
access_log = Path(access_name).read_text(encoding="utf-8")
if canary not in access_log:
    raise SystemExit("raw request URI did not reach the NGINX/WAF request path")
PY
    [ "$FUNCTIONAL_SCOPE" = full ] || return 0
    /usr/bin/grep -F 'phase=phase4_usr1 result=retained_secure_fd' "$lifecycle_log" >/dev/null || \
        fail "USR1 lifecycle did not retain the secure descriptor"
    /usr/bin/grep -F 'phase=phase4_reload_unsafe result=failed_old_cycle_preserved' "$lifecycle_log" >/dev/null || \
        fail "unsafe reload did not preserve the old active cycle"
    /usr/bin/grep -F 'phase=phase4_reload_secure result=new_validated_fd' "$lifecycle_log" >/dev/null || \
        fail "secure reload did not activate a new validated descriptor"
    /usr/bin/grep -F 'phase=shutdown mode=graceful_quit exit_status=0' "$lifecycle_log" >/dev/null || \
        fail "phase4 lifecycle did not perform a graceful successful shutdown"
    /usr/bin/grep -F 'phase=cleanup children=none result=passed' "$lifecycle_log" >/dev/null || \
        fail "phase4 lifecycle left worker children after cleanup"
    /usr/bin/grep -F 'phase=phase4_reload_overlap ' "$lifecycle_log" >/dev/null || \
        fail "phase4 lifecycle did not prove overlapping old and replacement workers"
    /usr/bin/grep -F 'phase=phase4_fd_shutdown result=closed_after_master_exit' "$lifecycle_log" >/dev/null || \
        fail "phase4 lifecycle did not prove descriptor closure with process cleanup"
}

assert_unconfigured_allow_control() {
    mode_root=$1
    allow_root="$mode_root/allow"
    [ -f "$allow_root/logs/observed-status.txt" ] || \
        fail "allow control has no observed status for mode=$CURRENT_MODE"
    [ "$(/bin/cat "$allow_root/logs/observed-status.txt")" = "200" ] || \
        fail "allow control was not accepted for mode=$CURRENT_MODE"
    [ ! -e "$allow_root/logs/phase4.log" ] && [ ! -L "$allow_root/logs/phase4.log" ] || \
        fail "unconfigured phase4 directive unexpectedly created an event sink"
}

assert_inheritance_and_override() {
    mode_root=$1
    inherited_log="$mode_root/inheritance/logs/phase4-server.log"
    override_log="$mode_root/override/logs/phase4.log"
    parent_log="$mode_root/override/logs/phase4-server.log"
    for expected_log in "$inherited_log" "$override_log"; do
        [ -s "$expected_log" ] || fail "missing inherited/overridden event log: $expected_log"
        /usr/bin/grep -F '"rule_id":"1101"' "$expected_log" >/dev/null || \
            fail "missing phase1 JSONL event in $expected_log"
    done
    [ ! -s "$parent_log" ] || \
        fail "child phase4 directive did not override the parent descriptor"
}

assert_mode_repair() {
    mode_root=$1
    repaired_log="$mode_root/mode-repair/logs/phase4.log"
    [ -f "$repaired_log" ] && [ ! -L "$repaired_log" ] || \
        fail "existing regular phase4 target disappeared"
    [ "$(/usr/bin/stat -c '%a' "$repaired_log")" = "600" ] || \
        fail "existing regular phase4 target was not normalized to 0600"
    /usr/bin/grep -F '"rule_id":"1100301"' "$repaired_log" >/dev/null || \
        fail "mode-repair control did not emit native JSONL"
}

[ "${NGINX_HOSTED_FUNCTIONAL_A:-0}" = "1" ] || \
    blocked "this exact gate must use the hosted functional-A launcher"
[ "$(/usr/bin/id -u)" = "0" ] || \
    blocked "hosted functional-A NGINX master must run as root"
[ -n "$FUNCTIONAL_ROOT" ] || blocked "missing NGINX_FUNCTIONAL_A_ROOT"
[ -n "$FUNCTIONAL_PARENT_ROOT" ] || blocked "missing NGINX_FUNCTIONAL_A_PARENT_ROOT"
[ "$FUNCTIONAL_ROOT" = "${VERIFIED_RUN_ROOT:-}" ] || \
    blocked "functional-A root must be the only verified runtime root"
[ "$FUNCTIONAL_ROOT" = "$FUNCTIONAL_PARENT_ROOT/nginx-hosted-functional-a" ] || \
    blocked "functional-A root must be the designated fresh child"
require_existing_non_symlink_directory "$FUNCTIONAL_PARENT_ROOT"
require_existing_non_symlink_directory "$MODSECURITY_LIB_DIR"
[ -d "$FRAMEWORK_ROOT" ] || blocked "missing Framework"
[ -f "$RULE_PREAMBLE" ] || blocked "missing pinned no-CRS rules"
[ -x "$NGINX_BINARY" ] || blocked "missing exact NGINX binary"
[ -f "$NGINX_MODULE" ] || blocked "missing exact NGINX module"
case "$FUNCTIONAL_RUNTIME_LIBRARY" in
    "$MODSECURITY_LIB_DIR/libmodsecurity.so.3") ;;
    *) blocked "missing bounded exact libmodsecurity runtime library" ;;
esac
require_existing_non_symlink_regular_file "$FUNCTIONAL_RUNTIME_LIBRARY"

require_fresh_worker_traversable_directory "$FUNCTIONAL_ROOT"
write_artifact_identity "$FUNCTIONAL_ROOT/artifact-identity.start.sha256"

for CURRENT_MODE in on off; do
    mode_root="$FUNCTIONAL_ROOT/$CURRENT_MODE"
    require_fresh_worker_traversable_directory "$mode_root"
    write_artifact_identity "$mode_root/artifact-identity.before.sha256"
    assert_same_artifact_identity "$FUNCTIONAL_ROOT/artifact-identity.start.sha256" \
        "$mode_root/artifact-identity.before.sha256"

    echo "nginx_exact_head: mode=$CURRENT_MODE phase4-functional"
    lifecycle_probe=0
    [ "$FUNCTIONAL_SCOPE" != full ] || lifecycle_probe=1
    run_harness_case "$mode_root" phase4 "$PHASE4_CASE" regular location "$lifecycle_probe" 1
    assert_phase4_jsonl_and_callback "$mode_root"

    if [ "$FUNCTIONAL_SCOPE" = full ]; then
    run_harness_case "$mode_root" allow "$ALLOW_CASE" regular location 0 0
    assert_unconfigured_allow_control "$mode_root"

    run_harness_case "$mode_root" inheritance "$INHERITANCE_CASE" regular server 0 0
    run_harness_case "$mode_root" override "$INHERITANCE_CASE" regular server_with_location_override 0 0
    assert_inheritance_and_override "$mode_root"

    run_harness_case "$mode_root" mode-repair "$PHASE4_CASE" existing_regular_0644 location 0 0
    assert_mode_repair "$mode_root"

    for unsafe_target in unsafe_symlink unsafe_fifo unsafe_directory unsafe_writable_parent unsafe_wrong_owner; do
        expect_config_rejection "$mode_root" "$unsafe_target"
    done
    fi

    write_artifact_identity "$mode_root/artifact-identity.after.sha256"
    assert_same_artifact_identity "$FUNCTIONAL_ROOT/artifact-identity.start.sha256" \
        "$mode_root/artifact-identity.after.sha256"
    echo "nginx_exact_head: mode=$CURRENT_MODE runtime=passed"
done

/usr/bin/cmp -s "$FUNCTIONAL_ROOT/on/artifact-identity.after.sha256" \
    "$FUNCTIONAL_ROOT/off/artifact-identity.after.sha256" || \
    fail "on/off cells did not use the same candidate artifact set"
publish_functional_evidence
if [ "$FUNCTIONAL_SCOPE" = full ]; then
    NGINX_REQUEST_BODY_LIMIT=1048576 \
    NGINX_REQUEST_BODY_NO_FILES_LIMIT=1048576 \
    NGINX_REQUEST_BODY_LIMIT_ACTION=Reject \
    /usr/bin/python3 -I "$SCRIPT_DIR/run_error_page_intervention.py"
fi
printf 'nginx_exact_head: scope=%s runtime=passed\n' "$FUNCTIONAL_SCOPE"
