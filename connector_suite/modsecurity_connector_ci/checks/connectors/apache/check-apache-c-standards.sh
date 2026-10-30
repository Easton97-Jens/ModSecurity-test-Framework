#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=$TEST_ROOT
CONNECTOR_ROOT="${CONNECTOR_ROOT:-$REPO_ROOT}"
FRAMEWORK_COMMON="$FRAMEWORK_ROOT/ci/lib/common.sh"

if [ ! -f "$FRAMEWORK_COMMON" ]; then
    echo "BLOCKED: apache_c_standards missing framework common.sh: $FRAMEWORK_COMMON"
    exit 77
fi

# shellcheck source=/dev/null
. "$FRAMEWORK_COMMON"

PROFILE=${APACHE_C_STD_PROFILE:-all}
CC_BIN=${CC:-cc}
OUT=${APACHE_C_STANDARDS_OUT:-/var/tmp/ModSecurity-conector-verified/build/apache-c-standards}

blocked() {
    if is_local_run; then
        echo "FAIL: apache_c_standards $*"
        exit 1
    fi
    echo "BLOCKED: apache_c_standards $*"
    exit 77
}

require_command_or_blocked "$CC_BIN" "apache_c_standards missing compiler: $CC_BIN"
APXS_BIN=$(require_or_provision_apxs)

APXS_CFLAGS=$($APXS_BIN -q CFLAGS 2>/dev/null || true)
APXS_CPPFLAGS=$($APXS_BIN -q CPPFLAGS 2>/dev/null || true)
APXS_INCLUDEDIR=$($APXS_BIN -q INCLUDEDIR 2>/dev/null || true)
APXS_INCLUDES=$($APXS_BIN -q INCLUDES 2>/dev/null || true)
APXS_BINDIR=$($APXS_BIN -q BINDIR 2>/dev/null || true)
APR_INCLUDES=""
APR_CONFIG=""
for APR_CONFIG_CANDIDATE in "$APXS_BINDIR/apr-1-config" "$APXS_BINDIR/apr-2-config" apr-1-config apr-2-config; do
    if [ -z "$APR_CONFIG_CANDIDATE" ]; then
        continue
    fi
    APR_CONFIG=$(ci_command_path "$APR_CONFIG_CANDIDATE" 2>/dev/null || true)
    if [ -n "$APR_CONFIG" ]; then
        break
    fi
done
if [ -n "$APR_CONFIG" ]; then
    APR_INCLUDES="$($APR_CONFIG --includes 2>/dev/null || true) $($APR_CONFIG --cppflags 2>/dev/null || true)"
fi

MODSECURITY_INCLUDE_FLAGS=$(modsecurity_include_flags_or_provision)

APXS_INCLUDEDIR_FLAG=""
if [ -n "$APXS_INCLUDEDIR" ]; then
    APXS_INCLUDEDIR_FLAG="-I$APXS_INCLUDEDIR"
fi

INCLUDES="-I$REPO_ROOT -I$REPO_ROOT/common/include -I$REPO_ROOT/connectors/apache/src $APXS_INCLUDEDIR_FLAG $APXS_INCLUDES $APR_INCLUDES $MODSECURITY_INCLUDE_FLAGS"

mkdir -p "$OUT"

HEADER_PROBE="$OUT/header-probe.c"
cat > "$HEADER_PROBE" <<'EOF'
#include "httpd.h"
#include "http_config.h"
#include "apr_tables.h"
#include <modsecurity/modsecurity.h>
int main(void) { return 0; }
EOF
if ! "$CC_BIN" -std=c17 $APXS_CFLAGS $APXS_CPPFLAGS $INCLUDES -c "$HEADER_PROBE" -o "$OUT/header-probe.o" >/dev/null 2>"$OUT/header-probe.err"; then
    cat "$OUT/header-probe.err"
    blocked "missing Apache/APR/libmodsecurity headers"
fi

APACHE_SOURCES="
connectors/apache/src/mod_security3.c
connectors/apache/src/msc_apache_mapper.c
connectors/apache/src/msc_config.c
connectors/apache/src/msc_filters.c
connectors/apache/src/msc_utils.c
"
PROFILE_REGISTRY_SOURCE="connectors/profile_registry.c"
COMMON_SOURCES="
common/src/config.c
common/src/config_parser.c
common/src/directive_spec.c
common/src/directive_adapter.c
common/src/request_helpers.c
common/src/response_helpers.c
common/src/request_mapper_contract.c
common/src/response_mapper_contract.c
common/src/headers.c
common/src/event.c
common/src/event_jsonl.c
common/src/json_escape.c
common/src/rule_id.c
common/src/log_sanitize.c
common/src/redaction.c
common/src/resource_limits.c
common/src/dos_guard.c
common/src/error.c
common/src/status.c
common/src/body_policy.c
common/src/intervention.c
common/src/block_statuses.c
common/src/http_status.c
common/src/transaction_state.c
common/src/late_intervention.c
common/src/limits.c
common/src/crs.c
"
SOURCES="$APACHE_SOURCES $PROFILE_REGISTRY_SOURCE $COMMON_SOURCES"

object_name() {
    path=$1
    echo "$path" | sed 's#[/.]#_#g'
}

compile_profile() {
    label=$1
    flags=$2
    for rel in $SOURCES; do
        src="$REPO_ROOT/$rel"
        obj="$OUT/$(object_name "$rel").$label.o"
        if ! "$CC_BIN" $flags $APXS_CFLAGS $APXS_CPPFLAGS $INCLUDES -c "$src" -o "$obj" >"$obj.out" 2>"$obj.err"; then
            cat "$obj.out"
            cat "$obj.err"
            echo "FAIL: apache_c_standards $label compile failed: $rel"
            exit 1
        fi
    done
    echo "PASS: apache_c_standards $label compile"
}

compile_optional() {
    profile=$1
    label=$2
    skip_message=$3
    set +e
    detected=$("${PYTHON:-python3}" -P "$REPO_ROOT/ci/provisioning/toolchains/detect-c-standard.py" --profile "$profile" --compiler "$CC_BIN" 2>"$OUT/detect-$profile.err")
    rc=$?
    set -e
    if [ "$rc" -eq 77 ]; then
        echo "$skip_message"
        return 0
    fi
    if [ "$rc" -ne 0 ]; then
        cat "$OUT/detect-$profile.err"
        exit "$rc"
    fi
    compile_profile "$label" "$detected -Wall -Wextra -Werror"
}

case "$PROFILE" in
    c17)
        compile_profile c17 "-std=c17 -Wall -Wextra -Werror"
        ;;
    c23)
        compile_optional c23 c23 "SKIPPED: optional Apache C23 check — compiler does not support c23/c2x"
        ;;
    c2y|future-c)
        compile_optional c2y c2y "SKIPPED: optional Apache future-C check — compiler does not support c2y/gnu2y"
        ;;
    all)
        compile_profile c17 "-std=c17 -Wall -Wextra -Werror"
        compile_optional c23 c23 "SKIPPED: optional Apache C23 check — compiler does not support c23/c2x"
        compile_optional c2y c2y "SKIPPED: optional Apache future-C check — compiler does not support c2y/gnu2y"
        ;;
    *)
        echo "usage: APACHE_C_STD_PROFILE={all|c17|c23|c2y} sh ci/checks/connectors/apache/check-apache-c-standards.sh" >&2
        exit 2
        ;;
esac
