#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=$TEST_ROOT
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$ROOT}"
REPO_ROOT="$ROOT"
FRAMEWORK_COMMON="$FRAMEWORK_ROOT/ci/lib/common.sh"

if [ ! -f "$FRAMEWORK_COMMON" ]; then
  echo "BLOCKED: nginx_c_standards missing framework common.sh: $FRAMEWORK_COMMON"
  exit 77
fi

# shellcheck source=/dev/null
. "$FRAMEWORK_COMMON"

CC_BIN=${CC:-cc}
PROFILE=${NGINX_C_STD_PROFILE:-all}
OUT=${BUILD_ROOT:-${TMPDIR:-/tmp}/modsecurity-conector-nginx-c-standards}/nginx-c-standards
mkdir -p "$OUT"
require_command_or_blocked "$CC_BIN" "nginx_c_standards missing C compiler: $CC_BIN"
NGINX_INCLUDE_FLAGS=$(nginx_include_flags_or_blocked)
MODSECURITY_INCLUDE_FLAGS=$(modsecurity_include_flags_or_blocked)
incs="-I$ROOT -I$ROOT/common/include -I$ROOT/connectors/nginx/src $NGINX_INCLUDE_FLAGS $MODSECURITY_INCLUDE_FLAGS"
compile_profile() {
  prof=$1
  case "$prof" in
    c17) std='-std=c17' ;;
    c23) std=$("${PYTHON:-python3}" -P "$ROOT/ci/provisioning/toolchains/detect-c-standard.py" --profile c23 --compiler "$CC_BIN") || { rc=$?; [ "$rc" = 77 ] && { echo "SKIPPED: optional C23 check unsupported"; return 0; }; return "$rc"; } ;;
    c2y) std=$("${PYTHON:-python3}" -P "$ROOT/ci/provisioning/toolchains/detect-c-standard.py" --profile c2y --compiler "$CC_BIN") || { rc=$?; [ "$rc" = 77 ] && { echo "SKIPPED: optional future-C check unsupported"; return 0; }; return "$rc"; } ;;
    *) echo "unknown profile $prof"; return 2 ;;
  esac
  files="connectors/nginx/src/ngx_http_modsecurity_module.c connectors/nginx/src/ngx_http_modsecurity_access.c connectors/nginx/src/ngx_http_modsecurity_header_filter.c connectors/nginx/src/ngx_http_modsecurity_body_filter.c connectors/nginx/src/ngx_http_modsecurity_log.c connectors/nginx/src/ngx_http_modsecurity_mapper.c connectors/profile_registry.c common/src/config.c common/src/config_parser.c common/src/directive_spec.c common/src/directive_adapter.c common/src/request_helpers.c common/src/response_helpers.c common/src/request_mapper_contract.c common/src/response_mapper_contract.c common/src/headers.c common/src/event.c common/src/transaction_state.c common/src/late_intervention.c common/src/event_jsonl.c common/src/json_escape.c common/src/rule_id.c common/src/log_sanitize.c common/src/redaction.c common/src/resource_limits.c common/src/dos_guard.c common/src/error.c common/src/status.c common/src/body_policy.c common/src/intervention.c common/src/crs.c common/src/block_statuses.c common/src/http_status.c"
  for f in $files; do
    [ -f "$ROOT/$f" ] || { echo "FAIL: nginx_c_standards missing listed source: $f" >&2; return 1; }
    obj="$OUT/$(echo "$prof-$f" | tr '/.' '__').o"
    "$CC_BIN" $std -Wall -Wextra -Werror $incs -c "$ROOT/$f" -o "$obj"
  done
  echo "PASS: nginx_c_standards $prof compile completed"
}
case "$PROFILE" in c17|c23|c2y) compile_profile "$PROFILE";; all) compile_profile c17; compile_profile c23; compile_profile c2y;; *) echo "unknown NGINX_C_STD_PROFILE=$PROFILE"; exit 2;; esac
