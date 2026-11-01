#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
# Run every selected connector through the strict, payload-free evidence
# profile.  The individual runner owns host provisioning and finalization;
# this wrapper deliberately continues after a failure so one fresh run ID
# records the outcome for every connector.
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
PYTHON=${PYTHON:-python3}
VERIFIED_RUN_ROOT=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}
VERIFIED_EVIDENCE_ROOT=${VERIFIED_EVIDENCE_ROOT:-$VERIFIED_RUN_ROOT/evidence}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$VERIFIED_EVIDENCE_ROOT/no-crs-evidence}
NO_CRS_RUN_ID=${NO_CRS_RUN_ID:-}
CONNECTORS=${NO_CRS_CONNECTORS:-"apache nginx haproxy envoy traefik lighttpd"}

[ -n "$NO_CRS_RUN_ID" ] || {
    echo "FAIL: NO_CRS_RUN_ID is required for a canonical all-connector full-lifecycle run" >&2
    exit 2
}
case "$NO_CRS_RUN_ID" in
    [A-Za-z0-9]* ) ;;
    *) echo "FAIL: unsafe NO_CRS_RUN_ID: $NO_CRS_RUN_ID" >&2; exit 2 ;;
esac
case "$NO_CRS_RUN_ID" in
    *[!A-Za-z0-9._-]*) echo "FAIL: unsafe NO_CRS_RUN_ID: $NO_CRS_RUN_ID" >&2; exit 2 ;;
    *) ;;
esac
[ "${#NO_CRS_RUN_ID}" -le 128 ] || {
    echo "FAIL: NO_CRS_RUN_ID is too long" >&2
    exit 2
}

summary_root=$EVIDENCE_ROOT/summary/$NO_CRS_RUN_ID
mkdir -p "$summary_root"
summary_file=$summary_root/full-lifecycle-run.jsonl
: > "$summary_file"

selected_profile() {
    requested_connector=$1
    case "$requested_connector" in
        apache) printf '%s\n' native-httpd-module ;;
        nginx) printf '%s\n' native-nginx-http-module ;;
        haproxy) printf '%s\n' native-htx-filter ;;
        envoy) printf '%s\n' ext_proc ;;
        traefik) printf '%s\n' native-middleware ;;
        lighttpd) printf '%s\n' patched-native ;;
        *) return 1 ;;
    esac
}

selected_target() {
    requested_connector=$1
    case "$requested_connector" in
        apache) printf '%s\n' full-lifecycle-apache ;;
        nginx) printf '%s\n' full-lifecycle-nginx ;;
        haproxy) printf '%s\n' full-lifecycle-haproxy-htx ;;
        envoy) printf '%s\n' full-lifecycle-envoy-ext-proc ;;
        traefik) printf '%s\n' full-lifecycle-traefik-native ;;
        lighttpd) printf '%s\n' full-lifecycle-lighttpd-patched ;;
        *) return 1 ;;
    esac
}

failed=0
blocked=0
for connector in $CONNECTORS; do
    profile=$(selected_profile "$connector") || {
        echo "FAIL: unsupported connector in full-lifecycle aggregate: $connector" >&2
        failed=1
        continue
    }
    target=$(selected_target "$connector") || {
        echo "FAIL: missing selected full-lifecycle target for $connector" >&2
        failed=1
        continue
    }
    rc=0
    NO_CRS_RUN_ID="$NO_CRS_RUN_ID" \
    NO_CRS_ARTIFACT_PROFILE=full_lifecycle \
    FULL_LIFECYCLE_HOST_PROFILE="$profile" \
    FULL_LIFECYCLE_EXECUTED_TARGET="$target" \
    EVIDENCE_ROOT="$EVIDENCE_ROOT" \
    sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-no-crs-baseline.sh" "$connector" no_crs_baseline || rc=$?
    "$PYTHON" - "$summary_file" "$connector" "$profile" "$target" "$rc" "$EVIDENCE_ROOT/$connector/$NO_CRS_RUN_ID/result.json" <<'PY'
import json
import sys
from pathlib import Path

output, connector, profile, target, rc, result_path = sys.argv[1:]
record = {
    "connector": connector,
    "selected_host_profile": profile,
    "selected_target": target,
    "runner_exit_code": int(rc),
    "result_path": result_path,
}
try:
    result = json.loads(Path(result_path).read_text(encoding="utf-8"))
except (OSError, ValueError):
    result = {}
record["status"] = result.get("status", "MISSING")
record["artifact_profile"] = result.get("artifact_profile", "")
record["host_profile"] = result.get("host_profile", "")
record["integration_mode"] = result.get("integration_mode", "")
record["executed_targets"] = result.get("executed_targets", [])
Path(output).open("a", encoding="utf-8").write(json.dumps(record, sort_keys=True) + "\n")
PY
    if [ "$rc" -eq 77 ]; then
        blocked=1
    elif [ "$rc" -ne 0 ]; then
        failed=1
    fi
done

set +e
"$PYTHON" "$FRAMEWORK_ROOT/ci/checks/catalog/no_crs_baseline.py" summarize \
    --evidence-root "$EVIDENCE_ROOT" \
    --run-id "$NO_CRS_RUN_ID" \
    --output-json "$summary_root/all-connectors-no-crs-summary.json" \
    --output-md "$summary_root/all-connectors-no-crs-summary.md" \
    --output-md-de "$summary_root/all-connectors-no-crs-summary.de.md"
summary_rc=$?
set -e
if [ "$summary_rc" -ne 0 ]; then
    failed=1
fi
if [ "$failed" -ne 0 ]; then
    exit 1
fi
if [ "$blocked" -ne 0 ]; then
    exit 77
fi
