#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
# One inventory-selected request through the actual C++/libmodsecurity evaluator.
set -eu
ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
PYTHON_BIN=${PYTHON:-python3}
: "${RUNNER_TEMP:?RUNNER_TEMP must be an explicit external test root}"
: "${MODSECURITY_INCLUDE_DIR:?an actual selected ModSecurity SDK include root is required}"
: "${MODSECURITY_LIB_DIR:?an actual selected ModSecurity SDK library root is required}"
"$PYTHON_BIN" -P - "$ROOT" "$RUNNER_TEMP" <<'ADMITROOT'
from pathlib import Path
import sys
from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
validate_output_root(Path(sys.argv[1]), Path(sys.argv[2]))
ADMITROOT
case_root=$(mktemp -d "$RUNNER_TEMP/active-targeted-evaluator.XXXXXX")
trap 'rm -rf -- "$case_root"' EXIT HUP INT TERM
CPP_BUILD_ROOT=$case_root/build
export CPP_BUILD_ROOT
sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/checks/analysis/check-targeted-evaluator-cpp17.sh"
cat > "$case_root/allow.conf" <<'RULES'
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:X-Modsec-Smoke "@streq inventory-deny-marker" "id:1000001,phase:1,deny,status:403,nolog"
RULES
"$CPP_BUILD_ROOT/modsecurity_targeted_eval" \
    --rule-file "$case_root/allow.conf" --ruleset targeted \
    --smoke-case targeted --uri /coverage-allow --method GET \
    > "$case_root/result.json"
"$PYTHON_BIN" -P - "$case_root/result.json" <<'PYCODE'
import json
from pathlib import Path
import sys

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {"ok": True, "decision_backend": "libmodsecurity",
            "modsecurity_rule_loaded": True, "intervention_disruptive": False,
            "intervention_status": 200, "request_method": "GET"}
if any(type(value.get(key)) is not type(wanted) or value[key] != wanted
       for key, wanted in expected.items()):
    raise SystemExit("actual C++ evaluator did not execute the selected allowed request")
print("ACTIVE_CPP_EVALUATOR_ALLOW_PASS")
PYCODE
