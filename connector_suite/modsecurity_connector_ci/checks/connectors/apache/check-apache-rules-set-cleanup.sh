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
FRAMEWORK_COMMON="$FRAMEWORK_ROOT/ci/lib/common.sh"
CC_BIN=${CC:-cc}
OUT=
BIN=

fail() {
    echo "FAIL: apache_rules_set_cleanup $*" >&2
    exit 2
}

validate_private_output_parent() {
    private_parent=$1

    while :; do
        if [ ! -d "$private_parent" ] || [ -L "$private_parent" ]; then
            fail "temporary output parent is not a non-symlink directory: $private_parent"
        fi
        private_parent_metadata=$(stat -c '%u %a' "$private_parent" 2>/dev/null) || \
            fail "cannot inspect temporary output parent: $private_parent"
        private_parent_owner=${private_parent_metadata%% *}
        private_parent_mode=${private_parent_metadata#* }
        case "$private_parent_mode" in
            ''|*[!0-7]*) fail "temporary output parent has an invalid mode: $private_parent" ;;
            *) : ;;
        esac
        if [ "$private_parent_owner" != "$CURRENT_UID" ] && [ "$private_parent_owner" != "0" ]; then
            fail "temporary output parent must be owned by the current user or root: $private_parent"
        fi
        private_parent_octal=0$private_parent_mode
        if [ "$((private_parent_octal & 022))" -ne 0 ] && \
            [ "$((private_parent_octal & 01000))" -eq 0 ]; then
            fail "temporary output parent permits group or other writes without sticky protection: $private_parent"
        fi
        [ "$private_parent" = "/" ] && return 0
        private_parent=$(dirname -- "$private_parent")
    done
}

cleanup_private_output() {
    if [ -n "$OUT" ] && [ -d "$OUT" ] && [ ! -L "$OUT" ]; then
        if [ -n "$BIN" ]; then
            rm -f -- "$BIN" || true
        fi
        rmdir -- "$OUT" 2>/dev/null || true
    fi
}

if [ ! -f "$FRAMEWORK_COMMON" ]; then
    echo "BLOCKED: apache_rules_set_cleanup missing framework common.sh: $FRAMEWORK_COMMON" >&2
    exit 77
fi

# shellcheck source=/dev/null
. "$FRAMEWORK_COMMON"

require_command_or_blocked "$CC_BIN" "apache_rules_set_cleanup missing compiler: $CC_BIN"
require_command_or_blocked mktemp "apache_rules_set_cleanup missing mktemp"
require_command_or_blocked stat "apache_rules_set_cleanup missing stat"
CURRENT_UID=$(id -u 2>/dev/null || true)
if [ -z "$CURRENT_UID" ]; then
    fail "cannot determine the current user"
fi

APXS_BIN=$(framework_find_apxs 2>/dev/null || true)
if [ -z "$APXS_BIN" ]; then
    skip_blocked "apache_rules_set_cleanup missing apxs/apxs2 with usable Apache headers"
fi

APXS_CFLAGS=$($APXS_BIN -q CFLAGS 2>/dev/null || true)
APXS_CPPFLAGS=$($APXS_BIN -q CPPFLAGS 2>/dev/null || true)
APXS_INCLUDEDIR=$($APXS_BIN -q INCLUDEDIR 2>/dev/null || true)
APXS_INCLUDES=$($APXS_BIN -q INCLUDES 2>/dev/null || true)
APXS_BINDIR=$($APXS_BIN -q BINDIR 2>/dev/null || true)
APR_CONFIG=
for APR_CONFIG_CANDIDATE in "$APXS_BINDIR/apr-1-config" "$APXS_BINDIR/apr-2-config" apr-1-config apr-2-config; do
    APR_CONFIG=$(ci_command_path "$APR_CONFIG_CANDIDATE" 2>/dev/null || true)
    if [ -n "$APR_CONFIG" ]; then
        break
    fi
done
if [ -z "$APR_CONFIG" ]; then
    skip_blocked "apache_rules_set_cleanup missing apr-1-config/apr-2-config"
fi

APR_INCLUDES=$($APR_CONFIG --includes 2>/dev/null || true)
APR_CPPFLAGS=$($APR_CONFIG --cppflags 2>/dev/null || true)
APR_LINK_FLAGS=$($APR_CONFIG --link-ld 2>/dev/null || true)
if [ -z "$APR_LINK_FLAGS" ]; then
    APR_LINK_FLAGS=$($APR_CONFIG --libs 2>/dev/null || true)
fi
if [ -z "$APR_LINK_FLAGS" ]; then
    skip_blocked "apache_rules_set_cleanup could not obtain APR link flags"
fi

APR_LIBDIR=
for APR_LINK_FLAG in $APR_LINK_FLAGS; do
    case "$APR_LINK_FLAG" in
        -L*)
            APR_LIBDIR=${APR_LINK_FLAG#-L}
            break
            ;;
        *) ;;
    esac
done

MODSECURITY_INCLUDE_FLAGS=$(modsecurity_include_flags_or_blocked)
APXS_INCLUDEDIR_FLAG=
if [ -n "$APXS_INCLUDEDIR" ]; then
    APXS_INCLUDEDIR_FLAG="-I$APXS_INCLUDEDIR"
fi
INCLUDES="-I$REPO_ROOT/connectors/apache/src -I$REPO_ROOT/common/include $APXS_INCLUDEDIR_FLAG $APXS_INCLUDES $APR_INCLUDES $APR_CPPFLAGS $MODSECURITY_INCLUDE_FLAGS"
APR_RPATH_FLAG=
if [ -n "$APR_LIBDIR" ] && [ -d "$APR_LIBDIR" ]; then
    APR_RPATH_FLAG="-Wl,-rpath,$APR_LIBDIR"
fi

TMP_PARENT=${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}
case "$TMP_PARENT" in
    /*) ;;
    *) fail "temporary output parent must be absolute: $TMP_PARENT" ;;
esac
TMP_PARENT=$(CDPATH= cd -- "$TMP_PARENT" && pwd -P) || \
    fail "cannot resolve temporary output parent: $TMP_PARENT"
validate_private_output_parent "$TMP_PARENT"
OUT=$(umask 077 && mktemp -d "$TMP_PARENT/.modsecurity-apache-rules-set-cleanup.XXXXXX") || \
    fail "cannot create a private temporary output directory"
if [ ! -d "$OUT" ] || [ -L "$OUT" ]; then
    fail "private temporary output is not a non-symlink directory: $OUT"
fi
OUT_METADATA=$(stat -c '%u %a' "$OUT" 2>/dev/null) || \
    fail "cannot inspect private temporary output: $OUT"
OUT_OWNER=${OUT_METADATA%% *}
OUT_MODE=${OUT_METADATA#* }
case "$OUT_MODE" in
    ''|*[!0-7]*) fail "private temporary output has an invalid mode: $OUT" ;;
    *) : ;;
esac
if [ "$OUT_OWNER" != "$CURRENT_UID" ]; then
    fail "private temporary output must be owned by the current user: $OUT"
fi
OUT_MODE_OCTAL=0$OUT_MODE
if [ "$((OUT_MODE_OCTAL & 077))" -ne 0 ]; then
    fail "private temporary output must not grant group or other access: $OUT"
fi

HARNESS="$SCRIPT_DIR/apache_rules_set_cleanup.c"
CONFIG="$REPO_ROOT/connectors/apache/src/msc_config.c"
BIN="$OUT/apache-rules-set-cleanup"
trap 'cleanup_private_output' EXIT

# APXS may enable LTO. The wrapper is referenced only after linker rewriting,
# so root it explicitly before LTO and section GC can discard its definition.
"$CC_BIN" -std=c17 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    $APXS_CFLAGS $APXS_CPPFLAGS -UNDEBUG $INCLUDES "$HARNESS" "$CONFIG" \
    -Wl,--gc-sections -Wl,--wrap=ap_log_perror_ \
    -Wl,--undefined=__wrap_ap_log_perror_ $APR_RPATH_FLAG $APR_LINK_FLAGS \
    -o "$BIN"
"$BIN"
