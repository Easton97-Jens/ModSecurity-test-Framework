#!/bin/sh

CONNECTOR_SMOKE_SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$CONNECTOR_SMOKE_SCRIPT_DIR/.." && pwd)}"
SOURCE_ROOT="${SOURCE_ROOT:-/src}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-conector-build}"
RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp}"
LOG_ROOT="${LOG_ROOT:-$BUILD_ROOT/logs}"

if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi

. "$CONNECTOR_SMOKE_SCRIPT_DIR/common.sh"

PYTHON_BIN="${PYTHON:-$(ci_python)}"

connector_smoke_require_src_path() {
    path=$1
    label=$2
    case "$path" in
        /src|/src/*) return 0 ;;
        /*) echo "BLOCKED: $label must be under /src: $path" >&2; exit 77 ;;
        *) echo "BLOCKED: $label must be absolute and under /src: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_require_build_path() {
    path=$1
    label=$2
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_require_results_path() {
    path=$1
    label=$2
    case "$path" in
        "$BUILD_ROOT/results"|"$BUILD_ROOT/results"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT/results: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_require_log_path() {
    path=$1
    label=$2
    case "$path" in
        "$BUILD_ROOT/logs"|"$BUILD_ROOT/logs"/*|"$BUILD_ROOT/results"|"$BUILD_ROOT/results"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT/logs or BUILD_ROOT/results: $path" >&2; exit 77 ;;
    esac
}

connector_smoke_validate_roots() {
    connector_smoke_require_src_path "$SOURCE_ROOT" SOURCE_ROOT
    connector_smoke_require_src_path "$BUILD_ROOT" BUILD_ROOT
    connector_smoke_require_build_path "$TMP_ROOT" TMP_ROOT
    connector_smoke_require_results_path "$RESULTS_DIR" RESULTS_DIR
    connector_smoke_require_log_path "$LOG_ROOT" LOG_ROOT
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
        SOURCE_ROOT="$SOURCE_ROOT" BUILD_ROOT="$BUILD_ROOT" RESULTS_DIR="$RESULTS_DIR" TMP_ROOT="$TMP_ROOT" LOG_ROOT="$LOG_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh "$harness_script"
    )
    rc=$?
    set -e
    results_jsonl="$RESULTS_DIR/$connector-results.jsonl"
    if [ "$rc" -eq 0 ] && [ ! -s "$results_jsonl" ]; then
        connector_smoke_write_evidence "$connector" BLOCKED 77 blocked "runtime harness produced no case evidence" "$harness_script"
        echo "$connector runtime smoke: BLOCKED - runtime harness produced no case evidence"
        echo "Runtime not verified"
        exit 77
    fi
    exit "$rc"
}
