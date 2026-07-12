#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CI_ROOT="${CI_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)}"
. "$CI_ROOT/lib/path-bootstrap.sh"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$CI_ROOT/lib/common.sh"

PROBE_ROOT="${RESPONSE_BODY_PROBE_ROOT:-$BUILD_ROOT/response-body-probe}"
RESULTS_ROOT="$PROBE_ROOT/results"
LOG_ROOT="$PROBE_ROOT/logs"
RUNTIME_ROOT="$PROBE_ROOT/runtime"
CASE_FILE="${RESPONSE_BODY_PROBE_CASE:-$FRAMEWORK_ROOT/tests/cases/response/body/response_body_basic_block.yaml}"
REPEAT="${RESPONSE_BODY_PROBE_REPEAT:-3}"

require_absolute_generated_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *) echo "probe_response_body: blocked $label must be absolute: $path"; exit 77 ;;
    esac
    assert_safe_runtime_path "$path" "$label" || exit 77
}

case "$REPEAT" in
    ''|*[!0-9]*)
        echo "probe_response_body: fail RESPONSE_BODY_PROBE_REPEAT must be a positive integer"
        exit 1
        ;;
    *) ;;
esac
if [ "$REPEAT" -lt 1 ]; then
    echo "probe_response_body: fail RESPONSE_BODY_PROBE_REPEAT must be >= 1"
    exit 1
fi

require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$PROBE_ROOT" "RESPONSE_BODY_PROBE_ROOT"
[ -f "$CASE_FILE" ] || { echo "probe_response_body: fail missing case file: $CASE_FILE"; exit 1; }

mkdir -p "$RESULTS_ROOT" "$LOG_ROOT" "$RUNTIME_ROOT"

run_probe_once() {
    connector=$1
    repeat=$2
    results_dir="$RESULTS_ROOT/$connector/repeat-$repeat"
    log_dir="$LOG_ROOT/$connector/repeat-$repeat"
    runtime_base="$RUNTIME_ROOT/$connector/repeat-$repeat"
    assert_safe_runtime_path "$results_dir" "probe results dir" || exit 77
    assert_safe_runtime_path "$log_dir" "probe log dir" || exit 77
    assert_safe_runtime_path "$runtime_base" "probe runtime dir" || exit 77
    mkdir -p "$results_dir" "$log_dir" "$runtime_base"
    chmod go+rx "$BUILD_ROOT" "$PROBE_ROOT" "$RUNTIME_ROOT" \
        "$RUNTIME_ROOT/$connector" "$runtime_base" 2>/dev/null || true

    case "$connector" in
        apache)
            script="$FRAMEWORK_ROOT/ci/runtime/run-apache-smoke.sh"
            runtime_env="APACHE_RUNTIME_LOG_DIR=$log_dir"
            ;;
        nginx)
            script="$FRAMEWORK_ROOT/ci/runtime/run-nginx-smoke.sh"
            runtime_env="NGINX_RUNTIME_LOG_DIR=$log_dir"
            ;;
        *)
            echo "probe_response_body: fail unknown connector $connector"
            exit 1
            ;;
    esac

    echo "probe_response_body: connector=$connector repeat=$repeat case=$CASE_FILE"
    set +e
    if [ "$connector" = "apache" ]; then
        RESULTS_DIR="$results_dir" \
            APACHE_RUNTIME_LOG_DIR="$log_dir" \
            RUNTIME_BASE="$runtime_base" \
            SMOKE_CASES="$CASE_FILE" \
            CASE_SCOPE=all \
            BUILD_ROOT="$BUILD_ROOT" \
            sh "$script"
    else
        RESULTS_DIR="$results_dir" \
            NGINX_RUNTIME_LOG_DIR="$log_dir" \
            RUNTIME_BASE="$runtime_base" \
            SMOKE_CASES="$CASE_FILE" \
            CASE_SCOPE=all \
            BUILD_ROOT="$BUILD_ROOT" \
            sh "$script"
    fi
    rc=$?
    set -e

    status=fail
    if [ "$rc" -eq 0 ]; then
        status=pass
    elif [ "$rc" -eq 77 ]; then
        status=blocked
    fi
    actual_status=""
    observed="$log_dir/response_body_basic_block/observed-status.txt"
    if [ -f "$observed" ]; then
        actual_status=$(cat "$observed")
    fi
    printf '%s\n' "$status" > "$results_dir/probe-status.txt"
    printf '%s\n' "$actual_status" > "$results_dir/probe-http-status.txt"
    set +e
    return "$rc"
}

apache_pass=0
apache_fail=0
apache_blocked=0
nginx_pass=0
nginx_fail=0
nginx_blocked=0

i=1
while [ "$i" -le "$REPEAT" ]; do
    set +e
    run_probe_once apache "$i"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        apache_pass=$((apache_pass + 1))
    elif [ "$rc" -eq 77 ]; then
        apache_blocked=$((apache_blocked + 1))
    else
        apache_fail=$((apache_fail + 1))
    fi

    set +e
    run_probe_once nginx "$i"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        nginx_pass=$((nginx_pass + 1))
    elif [ "$rc" -eq 77 ]; then
        nginx_blocked=$((nginx_blocked + 1))
    else
        nginx_fail=$((nginx_fail + 1))
    fi
    i=$((i + 1))
done

"$(ci_python)" - "$RESULTS_ROOT/response-body-probe-summary.json" \
    "$CASE_FILE" "$REPEAT" \
    "$apache_pass" "$apache_fail" "$apache_blocked" \
    "$nginx_pass" "$nginx_fail" "$nginx_blocked" \
    "$PROBE_ROOT" <<'PY'
import json
import pathlib
import sys

(
    output,
    case_file,
    repeat,
    apache_pass,
    apache_fail,
    apache_blocked,
    nginx_pass,
    nginx_fail,
    nginx_blocked,
    probe_root,
) = sys.argv[1:]

repeat_i = int(repeat)
summary = {
    "case": case_file,
    "probe_root": probe_root,
    "repeat": repeat_i,
    "apache": {
        "pass": int(apache_pass),
        "fail": int(apache_fail),
        "blocked": int(apache_blocked),
        "stable_pass": int(apache_pass) == repeat_i,
    },
    "nginx": {
        "pass": int(nginx_pass),
        "fail": int(nginx_fail),
        "blocked": int(nginx_blocked),
        "stable_pass": int(nginx_pass) == repeat_i,
    },
    "runs": {},
}
root = pathlib.Path(probe_root)
for connector in ("apache", "nginx"):
    connector_runs = []
    for index in range(1, repeat_i + 1):
        result_dir = root / "results" / connector / f"repeat-{index}"
        status_path = result_dir / "probe-status.txt"
        http_path = result_dir / "probe-http-status.txt"
        connector_runs.append(
            {
                "repeat": index,
                "status": status_path.read_text(encoding="utf-8").strip()
                if status_path.exists()
                else "missing",
                "http_status": http_path.read_text(encoding="utf-8").strip()
                if http_path.exists()
                else "",
                "log_dir": str(root / "logs" / connector / f"repeat-{index}" / "response_body_basic_block"),
            }
        )
    summary["runs"][connector] = connector_runs
if summary["apache"]["stable_pass"] and summary["nginx"]["stable_pass"]:
    summary["classification"] = "fully-imported-common-candidate"
elif summary["apache"]["stable_pass"] and not summary["nginx"]["stable_pass"]:
    summary["classification"] = "apache-only-candidate"
elif summary["nginx"]["stable_pass"] and not summary["apache"]["stable_pass"]:
    summary["classification"] = "nginx-only-candidate"
elif int(apache_blocked) or int(nginx_blocked):
    summary["classification"] = "blocked-or-mixed"
else:
    summary["classification"] = "not-promoted-mapped-only"

with open(output, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

cat "$RESULTS_ROOT/response-body-probe-summary.json"

if [ "$apache_pass" -eq "$REPEAT" ] && [ "$nginx_pass" -eq "$REPEAT" ]; then
    exit 0
fi
if [ "$apache_blocked" -gt 0 ] || [ "$nginx_blocked" -gt 0 ]; then
    exit 77
fi
exit 1
