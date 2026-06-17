#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"

if [ -n "${CONNECTOR_ROOT:-}" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$CONNECTOR_ROOT" && pwd)
elif [ -d "$FRAMEWORK_ROOT/../../connectors" ]; then
    CONNECTOR_ROOT=$(CDPATH= cd "$FRAMEWORK_ROOT/../.." && pwd)
else
    CONNECTOR_ROOT=$(pwd)
fi

. "$SCRIPT_DIR/common.sh"

SOURCE_ROOT="${SOURCE_ROOT:-/src}"
BUILD_ROOT="${BUILD_ROOT:-/src/ModSecurity-conector-build}"
RESULTS_DIR="${RESULTS_DIR:-$BUILD_ROOT/results}"
TMP_ROOT="${TMP_ROOT:-$BUILD_ROOT/tmp}"
LOG_ROOT="${LOG_ROOT:-$BUILD_ROOT/logs}"
STARTER_RESULTS_DIR="$RESULTS_DIR/connector-starters"
LOG_DIR="$STARTER_RESULTS_DIR/logs"
RESULTS_JSONL="$STARTER_RESULTS_DIR/results.jsonl"
SUMMARY_JSON="$STARTER_RESULTS_DIR/summary.json"
PYTHON_BIN="${PYTHON:-python3}"

require_safe_runtime_or_src() {
    path=$1
    label=$2
    case "$path" in
        /src|/src/*) return 0 ;;
        /*) assert_safe_runtime_path "$path" "$label" || exit 77 ;;
        *) echo "BLOCKED: $label must be absolute and under /src or a safe runtime root: $path" >&2; exit 77 ;;
    esac
}

require_under_build_root() {
    path=$1
    label=$2
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT: $path" >&2; exit 77 ;;
    esac
}

require_under_build_root_or_safe_runtime() {
    path=$1
    label=$2
    case "$path" in
        "$BUILD_ROOT"|"$BUILD_ROOT"/*) return 0 ;;
        *) require_safe_runtime_or_src "$path" "$label" ;;
    esac
}

require_results_root() {
    path=$1
    label=$2
    case "$path" in
        "$BUILD_ROOT/results"|"$BUILD_ROOT/results"/*) return 0 ;;
        *) echo "BLOCKED: $label must be under BUILD_ROOT/results: $path" >&2; exit 77 ;;
    esac
}

require_log_root() {
    path=$1
    label=$2
    case "$path" in
        "$BUILD_ROOT/logs"|"$BUILD_ROOT/logs"/*|"$BUILD_ROOT/results"|"$BUILD_ROOT/results"/*) return 0 ;;
        *) require_safe_runtime_or_src "$path" "$label" ;;
    esac
}

require_safe_runtime_or_src "$SOURCE_ROOT" SOURCE_ROOT
require_safe_runtime_or_src "$BUILD_ROOT" BUILD_ROOT
require_results_root "$RESULTS_DIR" RESULTS_DIR
require_under_build_root_or_safe_runtime "$TMP_ROOT" TMP_ROOT
require_log_root "$LOG_ROOT" LOG_ROOT

if [ ! -d "$CONNECTOR_ROOT/connectors" ]; then
    echo "BLOCKED: CONNECTOR_ROOT does not contain connectors/: $CONNECTOR_ROOT" >&2
    exit 77
fi

command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    echo "BLOCKED: missing Python interpreter: $PYTHON_BIN" >&2
    exit 77
}

mkdir -p "$TMP_ROOT" "$LOG_ROOT" "$LOG_DIR"
: > "$RESULTS_JSONL"

json_line() {
    connector=$1
    check=$2
    command_text=$3
    status=$4
    exit_code=$5
    stdout_log=$6
    stderr_log=$7
    notes=$8
    "$PYTHON_BIN" - "$RESULTS_JSONL" "$connector" "$check" "$command_text" \
        "$status" "$exit_code" "$stdout_log" "$stderr_log" "$notes" <<'PY'
import json
import sys

(
    output_path,
    connector,
    check,
    command_text,
    status,
    exit_code_text,
    stdout_log,
    stderr_log,
    notes,
) = sys.argv[1:]

exit_code = None if exit_code_text == "" else int(exit_code_text)
record = {
    "connector": connector,
    "check": check,
    "command": command_text,
    "status": status,
    "exit_code": exit_code,
    "test_type": "connector-starter",
    "runtime_verified": False,
    "runtime_status": "not-verified",
    "response_body_verified": False,
    "installs_global_artifacts": False,
    "stdout_log": stdout_log,
    "stderr_log": stderr_log,
    "notes": notes,
}
with open(output_path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True))
    handle.write("\n")
PY
}

has_make_target() {
    connector=$1
    target=$2
    makefile="$CONNECTOR_ROOT/connectors/$connector/Makefile"
    [ -f "$makefile" ] || return 1
    awk -v target="$target" '
        $0 ~ "^[[:alnum:]_.-]+[[:space:]]*:" {
            split($0, fields, ":")
            split(fields[1], targets, /[[:space:]]+/)
            for (idx in targets) {
                if (targets[idx] == target) {
                    found = 1
                }
            }
        }
        END { exit found ? 0 : 1 }
    ' "$makefile"
}

status_from_rc() {
    rc=$1
    if [ "$rc" -eq 0 ]; then
        printf '%s\n' PASS
    elif [ "$rc" -eq 77 ]; then
        printf '%s\n' BLOCKED
    else
        printf '%s\n' FAIL
    fi
}

run_check() {
    connector=$1
    check=$2
    command_text=$3
    required_type=$4
    required_value=$5
    notes=$6
    safe_name=$(printf '%s-%s' "$connector" "$check" | tr -c 'A-Za-z0-9_.-' '_')
    stdout_log="$LOG_DIR/$safe_name.stdout.log"
    stderr_log="$LOG_DIR/$safe_name.stderr.log"

    if [ "$required_type" = "make" ] && ! has_make_target "$connector" "$required_value"; then
        : > "$stdout_log"
        printf 'NOT_RUN: missing make target %s in connectors/%s/Makefile\n' "$required_value" "$connector" > "$stderr_log"
        json_line "$connector" "$check" "$command_text" NOT_RUN "" "$stdout_log" "$stderr_log" "$notes"
        return 0
    fi

    if [ "$required_type" = "file" ] && [ ! -f "$CONNECTOR_ROOT/$required_value" ]; then
        : > "$stdout_log"
        printf 'NOT_RUN: missing script %s\n' "$required_value" > "$stderr_log"
        json_line "$connector" "$check" "$command_text" NOT_RUN "" "$stdout_log" "$stderr_log" "$notes"
        return 0
    fi

    set +e
    (
        cd "$CONNECTOR_ROOT"
        SOURCE_ROOT="$SOURCE_ROOT" BUILD_ROOT="$BUILD_ROOT" TMP_ROOT="$TMP_ROOT" LOG_ROOT="$LOG_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" sh -c "$command_text"
    ) >"$stdout_log" 2>"$stderr_log"
    rc=$?
    set -e
    status=$(status_from_rc "$rc")
    json_line "$connector" "$check" "$command_text" "$status" "$rc" "$stdout_log" "$stderr_log" "$notes"
    return 0
}

starter_notes="build/self-test only; not runtime smoke validation"
clean_notes="cleanup/prep only; not runtime smoke validation"

run_check envoy clean "make -C connectors/envoy clean" make clean "$clean_notes"
run_check envoy build-starter "make -C connectors/envoy build-starter" make build-starter "$starter_notes"
run_check envoy self-test "make -C connectors/envoy self-test" make self-test "$starter_notes"

run_check haproxy clean "make -C connectors/haproxy clean" make clean "$clean_notes"
run_check haproxy build-metadata "make -C connectors/haproxy build-metadata" make build-metadata "$starter_notes"
run_check haproxy build-spoa-starter "make -C connectors/haproxy build-spoa-starter" make build-spoa-starter "$starter_notes"
run_check haproxy self-test-spoa "make -C connectors/haproxy self-test-spoa" make self-test-spoa "$starter_notes"

run_check lighttpd build-script "sh connectors/lighttpd/build/build_starter.sh" file connectors/lighttpd/build/build_starter.sh "$starter_notes"
run_check lighttpd build-starter "make -C connectors/lighttpd build-starter" make build-starter "$starter_notes"
run_check lighttpd build-bridge-starter "make -C connectors/lighttpd build-bridge-starter" make build-bridge-starter "$starter_notes"
run_check lighttpd self-test-bridge "make -C connectors/lighttpd self-test-bridge" make self-test-bridge "$starter_notes"

run_check traefik build-script "sh connectors/traefik/build/build-starter.sh build-starter" file connectors/traefik/build/build-starter.sh "$starter_notes"
run_check traefik build-decision-service "make -C connectors/traefik build-decision-service" make build-decision-service "$starter_notes"
run_check traefik self-test-decision-service "make -C connectors/traefik self-test-decision-service" make self-test-decision-service "$starter_notes"

"$PYTHON_BIN" - "$RESULTS_JSONL" "$SUMMARY_JSON" "$CONNECTOR_ROOT" "$SOURCE_ROOT" "$BUILD_ROOT" "$STARTER_RESULTS_DIR" <<'PY'
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

results_path, summary_path, connector_root, source_root, build_root, results_dir = sys.argv[1:]
records = []
with open(results_path, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if line:
            records.append(json.loads(line))

connectors = {}
counts_by_connector = defaultdict(Counter)
for record in records:
    counts_by_connector[record["connector"]][record["status"]] += 1

for connector in ("envoy", "haproxy", "lighttpd", "traefik"):
    connector_records = [record for record in records if record["connector"] == connector]
    counts = counts_by_connector[connector]
    connectors[connector] = {
        "counts": {
            "PASS": counts.get("PASS", 0),
            "FAIL": counts.get("FAIL", 0),
            "BLOCKED": counts.get("BLOCKED", 0),
            "NOT_RUN": counts.get("NOT_RUN", 0),
        },
        "checks": connector_records,
        "runtime_verified": False,
        "runtime_status": "not-verified",
        "response_body_verified": False,
    }

all_counts = Counter(record["status"] for record in records)
if all_counts.get("FAIL", 0):
    overall_status = "FAIL"
elif all_counts.get("BLOCKED", 0) or all_counts.get("NOT_RUN", 0):
    overall_status = "BLOCKED"
else:
    overall_status = "PASS"

summary = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "connector_root": connector_root,
    "source_root": source_root,
    "build_root": build_root,
    "results_dir": results_dir,
    "overall_status": overall_status,
    "overall_counts": {
        "PASS": all_counts.get("PASS", 0),
        "FAIL": all_counts.get("FAIL", 0),
        "BLOCKED": all_counts.get("BLOCKED", 0),
        "NOT_RUN": all_counts.get("NOT_RUN", 0),
    },
    "overall_runtime_verified": False,
    "note": "Connector starter checks are build/self-test evidence only and are not runtime smoke validation.",
    "connectors": connectors,
}

with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")

if overall_status == "FAIL":
    raise SystemExit(1)
if overall_status == "BLOCKED":
    raise SystemExit(77)
raise SystemExit(0)
PY
