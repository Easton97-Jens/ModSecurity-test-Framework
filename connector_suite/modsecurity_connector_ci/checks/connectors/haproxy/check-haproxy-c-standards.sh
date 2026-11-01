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
  echo "BLOCKED: haproxy_c_standards missing framework common.sh: $FRAMEWORK_COMMON"
  exit 77
fi

# shellcheck source=/dev/null
. "$FRAMEWORK_COMMON"

CC_BIN=${CC:-cc}
PROFILE=${HAPROXY_C_STD_PROFILE:-all}
OUT=${BUILD_ROOT:-${TMPDIR:-/tmp}/modsecurity-conector-haproxy-c-standards}/haproxy-c-standards
mkdir -p "$OUT"
require_command_or_blocked "$CC_BIN" "haproxy_c_standards missing C compiler: $CC_BIN"
HAPROXY_INCLUDE_FLAGS=$(require_or_provision_haproxy_headers)
MODSECURITY_INCLUDE_FLAGS=$(modsecurity_include_flags_or_provision)
incs="-I$ROOT -I$ROOT/common/include -I$ROOT/connectors/haproxy/src $HAPROXY_INCLUDE_FLAGS $MODSECURITY_INCLUDE_FLAGS"
probe_haproxy_headers() {
  std_flag=$1
  for header in haproxy/api.h haproxy/http.h haproxy/htx.h common/cfgparse.h types/global.h proto/proxy.h; do
    probe_src="$OUT/haproxy-header-probe-$(echo "$header" | tr '/.' '__').c"
    probe_obj="$OUT/haproxy-header-probe-$(echo "$header" | tr '/.' '__').o"
    {
      printf '#include <%s>\n' "$header"
      printf 'int main(void) { return 0; }\n'
    } > "$probe_src"
    if "$CC_BIN" $std_flag -Wall -Wextra -Werror $incs -c "$probe_src" -o "$probe_obj" >/dev/null 2>"$OUT/haproxy-header-probe.err"; then
      return 0
    fi
  done
  if is_local_run; then
    echo "FAIL: haproxy_c_standards missing usable HAProxy headers/source"
    exit 1
  fi
  echo "BLOCKED: haproxy_c_standards missing usable HAProxy headers/source"
  exit 77
}

compile_profile() {
  prof=$1
  case "$prof" in
    c17) std='-std=c17' ;;
    c23) std=$("${PYTHON:-python3}" -P "$ROOT/ci/provisioning/toolchains/detect-c-standard.py" --profile c23 --compiler "$CC_BIN") || { rc=$?; [ "$rc" = 77 ] && { echo "SKIPPED: optional C23 check unsupported"; return 0; }; return "$rc"; } ;;
    c2y) std=$("${PYTHON:-python3}" -P "$ROOT/ci/provisioning/toolchains/detect-c-standard.py" --profile c2y --compiler "$CC_BIN") || { rc=$?; [ "$rc" = 77 ] && { echo "SKIPPED: optional future-C check unsupported"; return 0; }; return "$rc"; } ;;
    *) echo "unknown profile $prof"; return 2 ;;
  esac
  probe_haproxy_headers "$std"
  files=""
  for dir in connectors/haproxy/src connectors/haproxy/runtime connectors/haproxy/spoa connectors/haproxy/harness; do
    if [ -d "$ROOT/$dir" ]; then
      for f in "$ROOT"/$dir/*.c; do [ -f "$f" ] && files="$files ${f#$ROOT/}"; done
    fi
  done
  files="$files common/src/config.c common/src/config_parser.c common/src/directive_spec.c common/src/directive_adapter.c common/src/request_helpers.c common/src/response_helpers.c common/src/request_mapper_contract.c common/src/response_mapper_contract.c common/src/headers.c common/src/event.c common/src/event_jsonl.c common/src/json_escape.c common/src/rule_id.c common/src/log_sanitize.c common/src/redaction.c common/src/resource_limits.c common/src/dos_guard.c common/src/error.c common/src/status.c common/src/body_policy.c common/src/crs.c common/src/transaction_state.c common/src/decision.c common/src/decision_action.c common/src/late_intervention.c common/src/flow_guard.c common/src/integrity_event.c common/src/rule_loader.c common/src/rule_merge.c common/src/artifacts.c common/src/artifact_layout.c common/src/block_statuses.c common/src/http_status.c common/src/path_policy.c common/src/intervention.c common/src/rule_error.c common/src/rule_event.c"
  for f in $files; do [ -f "$ROOT/$f" ] || continue; obj="$OUT/$(echo "$prof-$f" | tr '/.' '__').o"; "$CC_BIN" $std -Wall -Wextra -Werror $incs -c "$ROOT/$f" -o "$obj"; done
  for f in common/src/test_result.c common/src/test_result_json.c; do
    src="$TEST_ROOT/connector_suite/$f"
    [ -f "$src" ] || { echo "FAIL: haproxy_c_standards missing listed Framework source: $f" >&2; return 1; }
    obj="$OUT/$(echo "$prof-framework-$f" | tr '/.' '__').o"
    "$CC_BIN" $std -Wall -Wextra -Werror -I"$TEST_ROOT/connector_suite/common/include" $incs -c "$src" -o "$obj"
  done
  echo "PASS: haproxy_c_standards $prof compile completed"
}
case "$PROFILE" in c17|c23|c2y) compile_profile "$PROFILE";; all) compile_profile c17; compile_profile c23; compile_profile c2y;; *) echo "unknown HAPROXY_C_STD_PROFILE=$PROFILE"; exit 2;; esac
