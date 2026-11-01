#!/bin/sh
# Strict execution of one inventoried canonical two-case No-CRS profile.
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
PYTHON=${PYTHON:-python3}
connector=${1:?an inventoried connector is required}
case "$connector" in apache|haproxy|envoy|traefik|lighttpd) ;; *) echo "FAIL: connector is not inventoried" >&2; exit 2 ;; esac
NO_CRS_RUN_ID=${NO_CRS_RUN_ID:-$(date -u +%Y-%m-%dT%H-%M-%SZ)-$(git -C "$CONNECTOR_ROOT" rev-parse --short=8 HEAD)}
export NO_CRS_RUN_ID
verified_root=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}
evidence_root=${EVIDENCE_ROOT:-${VERIFIED_EVIDENCE_ROOT:-$verified_root/evidence}/no-crs-evidence}
sh "$SCRIPT_DIR/run-no-crs-baseline.sh" "$connector" minimal_runtime_smoke
"$PYTHON" "$FRAMEWORK_ROOT/ci/checks/catalog/no_crs_baseline.py" validate \
    --evidence-root "$evidence_root/$connector/$NO_CRS_RUN_ID" \
    --connector "$connector" --check all
"$PYTHON" - "$evidence_root/$connector/$NO_CRS_RUN_ID/result.json" <<'CHECK_RESULT'
import json
import sys
from pathlib import Path
value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("status") != "PASS":
    raise SystemExit("FAIL: canonical No-CRS behavior did not pass")
CHECK_RESULT
