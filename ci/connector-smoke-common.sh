#!/bin/sh

CONNECTOR_SMOKE_SCRIPT_DIR="${CONNECTOR_SMOKE_SCRIPT_DIR:-$(CDPATH= cd "$(dirname "$0")" && pwd)}"
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$CONNECTOR_SMOKE_SCRIPT_DIR/.." && pwd)}"

if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi

. "$CONNECTOR_SMOKE_SCRIPT_DIR/common.sh"

RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
PYTHON_BIN="${PYTHON:-$(ci_python)}"

connector_smoke_require_src_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
}

connector_smoke_require_runtime_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
}

connector_smoke_require_build_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_require_results_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_require_log_path() {
    path=$1
    label=$2
    assert_safe_runtime_path "$path" "$label" || exit 77
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_validate_roots() {
    connector_smoke_require_src_path "$SOURCE_ROOT" SOURCE_ROOT
    connector_smoke_require_runtime_path "$BUILD_ROOT" BUILD_ROOT
    connector_smoke_require_runtime_path "$TMP_ROOT" TMP_ROOT
    connector_smoke_require_runtime_path "$RESULTS_DIR" RESULTS_DIR
    connector_smoke_require_runtime_path "$LOG_ROOT" LOG_ROOT
    [ -d "$CONNECTOR_ROOT/connectors" ] || {
        echo "BLOCKED: CONNECTOR_ROOT does not contain connectors/: $CONNECTOR_ROOT" >&2
        exit 77
    }
    command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
        echo "BLOCKED: missing Python interpreter: $PYTHON_BIN" >&2
        exit 77
    }
    mkdir -p "$RESULTS_DIR" "$TMP_ROOT" "$LOG_ROOT"
}

connector_smoke_is_global_runtime_path() {
    path=$1
    case "$path" in
        /usr|/usr/*|/usr/local|/usr/local/*|/opt|/opt/*|/bin|/bin/*|/sbin|/sbin/*)
            return 0
            ;;
        *) return 1 ;;
    esac
}

connector_smoke_require_local_binary_path() {
    path=$1
    label=${2:-runtime binary}
    case "$path" in
        /*) ;;
        *)
            echo "BLOCKED: $label must be an explicit absolute local path, not a PATH lookup: $path" >&2
            return 77
            ;;
    esac
    if connector_smoke_is_global_runtime_path "$path"; then
        echo "BLOCKED: $label must not point at a global system path: $path" >&2
        return 77
    fi
    if [ ! -x "$path" ]; then
        echo "BLOCKED: $label is not executable: $path" >&2
        return 77
    fi
    return 0
}

find_runtime_binary_in_root() {
    root=$1
    binary_name=$2
    [ -n "$root" ] || return 1
    [ -d "$root" ] || return 1
    case "$root" in
        /usr|/usr/*|/usr/local|/usr/local/*|/opt|/opt/*|/bin|/bin/*|/sbin|/sbin/*)
            return 1
            ;;
    esac
    for candidate in \
        "$root/$binary_name" \
        "$root/bin/$binary_name" \
        "$root/sbin/$binary_name" \
        "$root/runtime/$binary_name" \
        "$root/runtime/bin/$binary_name" \
        "$root/$binary_name/bin/$binary_name" \
        "$root/$binary_name/sbin/$binary_name"
    do
        if [ -x "$candidate" ] && ! connector_smoke_is_global_runtime_path "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    find "$root" -maxdepth 6 -type f -name "$binary_name" -perm /111 2>/dev/null | while IFS= read -r candidate; do
        if ! connector_smoke_is_global_runtime_path "$candidate"; then
            printf '%s\n' "$candidate"
            break
        fi
    done | sed -n '1p'
}

find_runtime_binary() {
    env_var=$1
    binary_name=$2
    env_value=$(eval "printf '%s' \"\${$env_var:-}\"")
    if [ -n "$env_value" ]; then
        connector_smoke_require_local_binary_path "$env_value" "$env_var" || return 1
        printf '%s\n' "$env_value"
        return 0
    fi

    for root in \
        "${CONNECTOR_COMPONENT_CACHE:-}" \
        "${VERIFIED_COMPONENT_CACHE:-}" \
        "${VERIFIED_BUILD_ROOT:-}" \
        "${BUILD_ROOT:-}" \
        "${VERIFIED_RUN_ROOT:-}" \
        "${SOURCE_ROOT:-}"
    do
        found=$(find_runtime_binary_in_root "$root" "$binary_name" || true)
        if [ -n "$found" ]; then
            printf '%s\n' "$found"
            return 0
        fi
    done
    return 1
}

require_local_binary() {
    env_var=$1
    binary_name=$2
    find_runtime_binary "$env_var" "$binary_name"
}

resolve_evidence_root() {
    connector=$1
    if [ -n "${EVIDENCE_ROOT:-}" ]; then
        printf '%s\n' "$EVIDENCE_ROOT"
        return 0
    fi
    if [ -n "${VERIFIED_RUN_ROOT:-}" ]; then
        printf '%s/%s-smoke\n' "$VERIFIED_RUN_ROOT" "$connector"
        return 0
    fi
    printf '%s/results/%s-smoke\n' "$BUILD_ROOT" "$connector"
}

ensure_runtime_dirs() {
    evidence_root=${1:-}
    connector_smoke_validate_roots
    if [ -n "$evidence_root" ]; then
        connector_smoke_require_runtime_path "$evidence_root" EVIDENCE_ROOT
        mkdir -p "$evidence_root"
    fi
}

write_blocked_result() {
    connector=$1
    integration_mode=$2
    skipped_reason=$3
    missing_dependency=$4
    architecture_decision=${5:-}
    evidence_root=$(resolve_evidence_root "$connector")
    log_dir="${LOG_DIR:-$evidence_root/logs}"
    writer="$CONNECTOR_ROOT/common/scripts/write_smoke_result.py"
    starter_available=false
    if connector_smoke_starter_available "$connector"; then
        starter_available=true
    fi

    ensure_runtime_dirs "$evidence_root"
    connector_smoke_require_runtime_path "$log_dir" LOG_DIR
    mkdir -p "$log_dir"
    [ -f "$writer" ] || {
        echo "BLOCKED: common smoke result writer missing: $writer" >&2
        exit 77
    }

    "$PYTHON_BIN" "$writer" \
        --connector "$connector" \
        --integration-mode "$integration_mode" \
        --status BLOCKED \
        --exit-code 77 \
        --runtime-verified false \
        --response-body-verified false \
        --allowed-request-status not-run \
        --blocked-request-status not-run \
        --evidence-root "$evidence_root" \
        --results-dir "$RESULTS_DIR" \
        --connector-root "$CONNECTOR_ROOT" \
        --source-root "$SOURCE_ROOT" \
        --build-root "$BUILD_ROOT" \
        --tmp-root "$TMP_ROOT" \
        --log-root "$LOG_ROOT" \
        --log-dir "$log_dir" \
        --harness-path "${HARNESS_PATH:-}" \
        --skipped-reason "$skipped_reason" \
        --starter-checks-available "$starter_available" \
        --missing-dependency "$missing_dependency" \
        --architecture-decision "$architecture_decision"
}

connector_skip_missing_dependency() {
    connector=$1
    integration_mode=$2
    skipped_reason=$3
    missing_dependency=$4
    architecture_decision=${5:-}
    write_blocked_result "$connector" "$integration_mode" "$skipped_reason" "$missing_dependency" "$architecture_decision"
    echo "$connector runtime smoke: BLOCKED - $skipped_reason"
    echo "Runtime not verified"
    echo "Evidence root: $(resolve_evidence_root "$connector")"
    exit 77
}

connector_smoke_starter_available() {
    connector=$1
    if [ -f "$CONNECTOR_ROOT/connectors/$connector/Makefile" ]; then
        return 0
    fi
    if [ -d "$CONNECTOR_ROOT/connectors/$connector/build" ]; then
        return 0
    fi
    return 1
}

connector_smoke_write_evidence() {
    connector=$1
    status=$2
    exit_code=$3
    runtime_status=$4
    reason=$5
    harness_path=$6
    results_jsonl="$RESULTS_DIR/$connector-results.jsonl"
    summary_json="$RESULTS_DIR/$connector-summary.json"
    summary_text="$RESULTS_DIR/$connector-summary.txt"
    starter_available=false
    if connector_smoke_starter_available "$connector"; then
        starter_available=true
    fi
    "$PYTHON_BIN" - "$results_jsonl" "$summary_json" "$summary_text" \
        "$connector" "$status" "$exit_code" "$runtime_status" "$reason" \
        "$harness_path" "$starter_available" "$CONNECTOR_ROOT" "$SOURCE_ROOT" \
        "$BUILD_ROOT" "$RESULTS_DIR" "$TMP_ROOT" "$LOG_ROOT" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    results_jsonl,
    summary_json,
    summary_text,
    connector,
    status,
    exit_code_text,
    runtime_status,
    reason,
    harness_path,
    starter_available_text,
    connector_root,
    source_root,
    build_root,
    results_dir,
    tmp_root,
    log_root,
) = sys.argv[1:]

exit_code = int(exit_code_text)
starter_available = starter_available_text == "true"
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
note = "Build/self-test starter evidence is available via make connector-starter-checks but is not runtime smoke evidence."
record = {
    "connector": connector,
    "test_type": "runtime-smoke",
    "status": status,
    "exit_code": exit_code,
    "runtime_verified": False,
    "runtime_status": runtime_status,
    "response_body_verified": False,
    "reason": reason,
    "starter_checks_available": starter_available,
    "installs_global_artifacts": False,
    "harness_path": harness_path,
    "generated_at": now,
    "note": note,
}
counts = {"PASS": 0, "FAIL": 0, "BLOCKED": 0, "NOT_RUN": 0}
counts[status] = counts.get(status, 0) + 1
summary = {
    "connector": connector,
    "generated_at": now,
    "connector_root": connector_root,
    "source_root": source_root,
    "build_root": build_root,
    "results_dir": results_dir,
    "tmp_root": tmp_root,
    "log_root": log_root,
    "status": status,
    "counts": counts,
    "runtime_verified": False,
    "runtime_status": runtime_status,
    "response_body_verified": False,
    "reason": reason,
    "starter_checks_available": starter_available,
    "installs_global_artifacts": False,
    "harness_path": harness_path,
    "note": note,
    "results": [record],
}
with open(results_jsonl, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True))
    handle.write("\n")
with open(summary_json, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
with open(summary_text, "w", encoding="utf-8") as handle:
    handle.write(f"{status} {connector}-runtime-smoke {reason}\n")
    handle.write("Runtime not verified\n")
    handle.write(f"{note}\n")
PY
}

connector_smoke_run() {
    connector=$1
    harness_script=$2
    connector_smoke_validate_roots
    connector_dir="$CONNECTOR_ROOT/connectors/$connector"
    [ -d "$connector_dir" ] || {
        connector_smoke_write_evidence "$connector" BLOCKED 77 blocked "connector directory missing" "$harness_script"
        exit 77
    }
    if [ ! -x "$harness_script" ]; then
        connector_smoke_write_evidence "$connector" BLOCKED 77 blocked "runtime harness not implemented" "$harness_script"
        echo "$connector runtime smoke: BLOCKED - runtime harness not implemented"
        echo "Runtime not verified"
        exit 77
    fi
    set +e
    (
        cd "$CONNECTOR_ROOT"
        SOURCE_ROOT="$SOURCE_ROOT" BUILD_ROOT="$BUILD_ROOT" RESULTS_DIR="$RESULTS_DIR" TMP_ROOT="$TMP_ROOT" LOG_ROOT="$LOG_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" FRAMEWORK_ROOT="$FRAMEWORK_ROOT" sh "$harness_script"
    )
    rc=$?
    set -e
    results_jsonl="$RESULTS_DIR/$connector-results.jsonl"
    if [ "$rc" -eq 0 ] && [ "${RUN_ONE_CASE:-0}" = "1" ]; then
        case_result_path="${LOG_DIR:-$LOG_ROOT/$connector-runtime}/result.json"
        if [ -s "$case_result_path" ]; then
            exit 0
        fi
    fi
    if [ "$rc" -eq 0 ] && [ ! -s "$results_jsonl" ]; then
        connector_smoke_write_evidence "$connector" BLOCKED 77 blocked "runtime harness produced no case evidence" "$harness_script"
        echo "$connector runtime smoke: BLOCKED - runtime harness produced no case evidence"
        echo "Runtime not verified"
        exit 77
    fi
    exit "$rc"
}
