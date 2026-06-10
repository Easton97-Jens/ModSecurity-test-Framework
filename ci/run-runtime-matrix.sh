#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)}"
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$(pwd)}"
REPO_ROOT="$CONNECTOR_ROOT"
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/mrts-common.sh"

PYTHON_BIN="${PYTHON:-$(ci_python)}"
FORCE_ALL_CASES="${FORCE_ALL_CASES:-0}"
SNAPSHOT_ARGS=""
if [ "$FORCE_ALL_CASES" = "1" ]; then
    SNAPSHOT_ARGS="--force-all"
    echo "runtime-matrix: FORCE_ALL_CASES=1; all materializable YAML cases will be attempted where applicable"
fi

echo "runtime-matrix: running Apache smoke with REFRESH=1"
set +e
REFRESH=1 SKIP_RUNTIME_COMPONENT_PREPARE=1 RESULTS_DIR="$BUILD_ROOT/results" FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" make -C "$CONNECTOR_ROOT" smoke-apache
apache_rc=$?
set -e
echo "runtime-matrix: Apache smoke exit=$apache_rc"

echo "runtime-matrix: running NGINX smoke with REFRESH=1"
set +e
REFRESH=1 SKIP_RUNTIME_COMPONENT_PREPARE=1 RESULTS_DIR="$BUILD_ROOT/results" FRAMEWORK_ROOT="$FRAMEWORK_ROOT" CONNECTOR_ROOT="$CONNECTOR_ROOT" make -C "$CONNECTOR_ROOT" smoke-nginx
nginx_rc=$?
set -e
echo "runtime-matrix: NGINX smoke exit=$nginx_rc"

"$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/update-runtime-snapshot.py" \
    --framework-root "$FRAMEWORK_ROOT" \
    --connector-root "$CONNECTOR_ROOT" \
    --output-root "$CONNECTOR_ROOT" \
    --build-root "$BUILD_ROOT" \
    --apache-exit-code "$apache_rc" \
    --nginx-exit-code "$nginx_rc" \
    $SNAPSHOT_ARGS
prepare_mrts_variant
if [ "$MODSECURITY_MRTS_VARIANT" = "with-mrts" ]; then
    mrts_import_cases
fi

"$PYTHON_BIN" "$FRAMEWORK_ROOT/ci/generate-case-matrix.py" \
    --framework-root "$FRAMEWORK_ROOT" \
    --connector-root "$CONNECTOR_ROOT" \
    --output-root "$CONNECTOR_ROOT"

if [ "$FORCE_ALL_CASES" = "1" ]; then
    if "$PYTHON_BIN" - "$BUILD_ROOT/results/apache-summary.json" "$BUILD_ROOT/results/nginx-summary.json" <<'PY'
import json
import sys
from pathlib import Path

for path_arg, connector in [(sys.argv[1], "apache"), (sys.argv[2], "nginx")]:
    path = Path(path_arg)
    if not path.exists():
        raise SystemExit(f"missing summary: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = data.get(connector, {}).get("cases", {})
    if not isinstance(cases, dict) or not cases:
        raise SystemExit(f"missing per-case runtime evidence in {path}")
PY
    then
        echo "runtime-matrix: force-all completed; observed case failures are recorded as runtime evidence, not command failure"
        exit 0
    fi
    echo "runtime-matrix: force-all did not produce complete per-connector summaries"
    exit 1
fi

if [ "$apache_rc" -ne 0 ] || [ "$nginx_rc" -ne 0 ]; then
    echo "runtime-matrix: one or more runtime smokes failed or blocked; generated docs were still refreshed from available evidence"
    exit 1
fi

echo "runtime-matrix: Apache and NGINX runtime matrix completed"
