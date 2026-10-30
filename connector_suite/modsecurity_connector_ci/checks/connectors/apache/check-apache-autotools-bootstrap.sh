#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
TEST_PARENT=${APACHE_AUTOTOOLS_TEST_PARENT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}}
RUNTIME_PARENT=${APACHE_AUTOTOOLS_RUNTIME_PARENT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}}
WORK_ROOT=
RUNTIME_ROOT=
HTTPD_PID=

blocked() {
    echo "BLOCKED: apache-autotools-bootstrap $*" >&2
    exit 77
}

HTTP_STATUS_FORMAT='%{http_code}'
TXID_LENGTH_PREFIX="/__modsec_txid_length/"

txid_path_for_length() {
    expected_length=$1
    prefix_length=${#TXID_LENGTH_PREFIX}
    if [ "$expected_length" -le "$prefix_length" ]; then
        blocked "transaction identifier test length is too short: $expected_length"
    fi
    suffix_length=$((expected_length - prefix_length))
    suffix=$(printf '%*s' "$suffix_length" '' | tr ' ' x)
    printf '%s%s\n' "$TXID_LENGTH_PREFIX" "$suffix"
}

TXID_127_PATH=$(txid_path_for_length 127)
TXID_128_PATH=$(txid_path_for_length 128)
TXID_LONG_PATH=$(txid_path_for_length 192)

fail() {
    echo "FAIL: apache-autotools-bootstrap $*" >&2
    if [ -n "${RUNTIME_ROOT:-}" ]; then
        for log_file in \
            "${CONFIGTEST_LOG:-}" \
            "${MODULES_LOG:-}" \
            "${HTTPD_LOG:-}"
        do
            if [ -f "$log_file" ]; then
                echo "apache-autotools-bootstrap: Apache log follows: $log_file" >&2
                sed -n '1,160p' "$log_file" >&2
            fi
        done
    fi
    exit 1
}

require_command() {
    command_name=$1
    command -v "$command_name" >/dev/null 2>&1 || \
        blocked "missing required command: $command_name"
}

canonicalize_command() {
    candidate=$1
    case "$candidate" in
        /*)
            printf '%s\n' "$candidate"
            ;;
        *)
            command -v "$candidate" 2>/dev/null || true
            ;;
    esac
}

safe_remove_work_root() {
    [ -n "$WORK_ROOT" ] || return 0
    case "$WORK_ROOT" in
        "$TEST_PARENT"/f-gs-001-apache-autotools.*) ;;
        *)
            echo "FAIL: apache-autotools-bootstrap refused unsafe cleanup path: $WORK_ROOT" >&2
            return 1
            ;;
    esac
    [ ! -L "$WORK_ROOT" ] || {
        echo "FAIL: apache-autotools-bootstrap refused symlink cleanup path: $WORK_ROOT" >&2
        return 1
    }
    [ ! -e "$WORK_ROOT" ] || rm -rf -- "$WORK_ROOT"
}

safe_remove_runtime_root() {
    [ -n "$RUNTIME_ROOT" ] || return 0
    case "$RUNTIME_ROOT" in
        "$RUNTIME_PARENT"/f-gs-001-apache-runtime.*) ;;
        *)
            echo "FAIL: apache-autotools-bootstrap refused unsafe runtime cleanup path: $RUNTIME_ROOT" >&2
            return 1
            ;;
    esac
    [ ! -L "$RUNTIME_ROOT" ] || {
        echo "FAIL: apache-autotools-bootstrap refused symlink runtime cleanup path: $RUNTIME_ROOT" >&2
        return 1
    }
    [ ! -e "$RUNTIME_ROOT" ] || rm -rf -- "$RUNTIME_ROOT"
}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$HTTPD_PID" ] && kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
        kill "$HTTPD_PID" >/dev/null 2>&1 || true
        wait "$HTTPD_PID" >/dev/null 2>&1 || true
    fi
    if ! safe_remove_runtime_root; then
        status=1
    fi
    if ! safe_remove_work_root; then
        status=1
    fi
    exit "$status"
}

trap cleanup EXIT HUP INT TERM

case "$TEST_PARENT" in
    /*) ;;
    *) blocked "APACHE_AUTOTOOLS_TEST_PARENT must be absolute: $TEST_PARENT" ;;
esac
[ -d "$TEST_PARENT" ] || blocked "test parent does not exist: $TEST_PARENT"
TEST_PARENT=$(CDPATH='' cd -- "$TEST_PARENT" && pwd -P)
case "$RUNTIME_PARENT" in
    /*) ;;
    *) blocked "APACHE_AUTOTOOLS_RUNTIME_PARENT must be absolute: $RUNTIME_PARENT" ;;
esac
[ -d "$RUNTIME_PARENT" ] || blocked "runtime parent does not exist: $RUNTIME_PARENT"
RUNTIME_PARENT=$(CDPATH='' cd -- "$RUNTIME_PARENT" && pwd -P)
WORK_ROOT=$(mktemp -d "$TEST_PARENT/f-gs-001-apache-autotools.XXXXXX") || \
    blocked "could not create a private task directory under $TEST_PARENT"
RUNTIME_ROOT=$(mktemp -d "$RUNTIME_PARENT/f-gs-001-apache-runtime.XXXXXX") || \
    blocked "could not create an isolated runtime directory under $RUNTIME_PARENT"

for required_command in git tar autoreconf make python3 curl id cmp; do
    require_command "$required_command"
done

APXS_BIN=${APXS:-}
if [ -z "$APXS_BIN" ]; then
    APXS_BIN=$(canonicalize_command apxs)
fi
if [ -z "$APXS_BIN" ]; then
    APXS_BIN=$(canonicalize_command apxs2)
fi
[ -n "$APXS_BIN" ] || blocked "missing APXS; set APXS to an executable"
[ -x "$APXS_BIN" ] || blocked "APXS is not executable: $APXS_BIN"

HTTPD_BIN=${HTTPD_BIN:-${APACHE_HTTPD_BIN:-}}
if [ -z "$HTTPD_BIN" ]; then
    APXS_SBINDIR=$("$APXS_BIN" -q SBINDIR 2>/dev/null || true)
    APXS_PROGNAME=$("$APXS_BIN" -q PROGNAME 2>/dev/null || true)
    [ -n "$APXS_SBINDIR" ] && [ -n "$APXS_PROGNAME" ] || \
        blocked "APXS did not report SBINDIR and PROGNAME"
    HTTPD_BIN="$APXS_SBINDIR/$APXS_PROGNAME"
fi
HTTPD_BIN=$(canonicalize_command "$HTTPD_BIN")
[ -n "$HTTPD_BIN" ] || blocked "missing Apache httpd executable"
[ -x "$HTTPD_BIN" ] || blocked "Apache httpd is not executable: $HTTPD_BIN"

MODSECURITY_PREFIX=${MODSECURITY_PREFIX:-/usr}
case "$MODSECURITY_PREFIX" in
    /*) ;;
    *) blocked "MODSECURITY_PREFIX must be absolute: $MODSECURITY_PREFIX" ;;
esac

ARCHIVE="$WORK_ROOT/parent-source.tar"
PATCH_FILE="$WORK_ROOT/tracked-worktree.patch"
SOURCE_ROOT="$WORK_ROOT/source"
APACHE_ROOT="$SOURCE_ROOT/connectors/apache"
MODULES_FILE="$RUNTIME_ROOT/conf/modules.load"
CONFIG_FILE="$RUNTIME_ROOT/conf/httpd.conf"
ROOT_LOG_DIR="$RUNTIME_ROOT/logs/root"
HTTPD_LOG_DIR="$RUNTIME_ROOT/logs/httpd"
CONFIGTEST_LOG="$ROOT_LOG_DIR/configtest.log"
MODULES_LOG="$ROOT_LOG_DIR/modules.log"
HTTPD_LOG="$ROOT_LOG_DIR/httpd.log"
HTTPD_ERROR_LOG="$HTTPD_LOG_DIR/error.log"
PORT_START=${APACHE_AUTOTOOLS_PORT_START:-18880}
PORT_SEARCH_LIMIT=${APACHE_AUTOTOOLS_PORT_SEARCH_LIMIT:-50}

case "$PORT_START:$PORT_SEARCH_LIMIT" in
    *[!0-9:]*|:*|*:) blocked "port settings must be positive decimal integers" ;;
    *) ;;
esac
[ "$PORT_START" -gt 0 ] && [ "$PORT_START" -lt 65536 ] || \
    blocked "APACHE_AUTOTOOLS_PORT_START is outside 1..65535: $PORT_START"
[ "$PORT_SEARCH_LIMIT" -gt 0 ] || \
    blocked "APACHE_AUTOTOOLS_PORT_SEARCH_LIMIT must be positive: $PORT_SEARCH_LIMIT"

git -C "$REPO_ROOT" archive --format=tar HEAD -o "$ARCHIVE"
mkdir -p "$SOURCE_ROOT"
tar -xf "$ARCHIVE" -C "$SOURCE_ROOT"
# A clean checkout (including CI) leaves this patch empty, so SOURCE_ROOT is
# exactly the HEAD archive.  For a pre-commit local run, retain only tracked
# changes; untracked files are never copied into the source snapshot.
git -C "$REPO_ROOT" diff --no-ext-diff --binary --full-index HEAD > "$PATCH_FILE"
if [ -s "$PATCH_FILE" ]; then
    git -C "$SOURCE_ROOT" apply --whitespace=nowarn "$PATCH_FILE"
fi

[ ! -e "$SOURCE_ROOT/.git" ] || fail "source copy unexpectedly contains Git metadata"
for required_source in \
    connectors/apache/configure.ac \
    connectors/apache/Makefile.am \
    connectors/apache/build/apxs-wrapper.in \
    connectors/apache/src/mod_security3.c \
    common/include/msconnector/directives.h
do
    [ -f "$SOURCE_ROOT/$required_source" ] || \
        fail "source archive is missing tracked input: $required_source"
done
for forbidden_artifact in configure aclocal.m4 Makefile autom4te.cache; do
    [ ! -e "$APACHE_ROOT/$forbidden_artifact" ] || \
        fail "fresh source copy unexpectedly contains generated artifact: $forbidden_artifact"
done

(
    cd "$APACHE_ROOT"
    autoreconf --install
)
test -f "$APACHE_ROOT/configure"
test -x "$APACHE_ROOT/configure"
(
    cd "$APACHE_ROOT"
    ./configure \
        "--with-libmodsecurity=$MODSECURITY_PREFIX" \
        "--with-apxs=$APXS_BIN" \
        "--with-apache=$HTTPD_BIN"
)
MAKE_LOG="$WORK_ROOT/autotools-make.log"
if ! (
    cd "$APACHE_ROOT"
    CONNECTOR_ROOT="$SOURCE_ROOT" \
    MSCONNECTOR_COMMON_INC="$SOURCE_ROOT/common/include" \
    MSCONNECTOR_COMMON_SRC="$SOURCE_ROOT/common/src" \
    MSCONNECTOR_COMMON_BUILD_SRC="$APACHE_ROOT/build/common-src" \
    MSCONNECTOR_PROFILE_REGISTRY_BUILD_ROOT="$WORK_ROOT/profile-registry" \
    make
) > "$MAKE_LOG" 2>&1; then
    sed -n '1,220p' "$MAKE_LOG" >&2
    fail "Autotools make failed"
fi

MODULE_PATH="$APACHE_ROOT/src/.libs/mod_security3.so"
test -f "$MODULE_PATH" || fail "Autotools make completed without module: $MODULE_PATH"
RUNTIME_MODULE_PATH="$RUNTIME_ROOT/modules/mod_security3.so"

apache_modules_dir() {
    modules_dir=$("$APXS_BIN" -q LIBEXECDIR 2>/dev/null || true)
    if [ -n "$modules_dir" ] && [ -d "$modules_dir" ]; then
        printf '%s\n' "$modules_dir"
        return 0
    fi
    modules_dir=$("$APXS_BIN" -q LIBDIR 2>/dev/null || true)
    if [ -n "$modules_dir" ] && [ -d "$modules_dir/modules" ]; then
        printf '%s/modules\n' "$modules_dir"
        return 0
    fi
    return 1
}

append_module_if_present() {
    module_name=$1
    module_file=$2
    module_path="$APACHE_MODULES_DIR/$module_file"
    if [ -f "$module_path" ]; then
        printf 'LoadModule %s "%s"\n' "$module_name" "$module_path" >> "$MODULES_FILE"
    fi
}

append_mpm_if_needed() {
    for mpm in event worker prefork; do
        module_path="$APACHE_MODULES_DIR/mod_mpm_$mpm.so"
        if [ -f "$module_path" ]; then
            printf 'LoadModule mpm_%s_module "%s"\n' "$mpm" "$module_path" >> "$MODULES_FILE"
            return 0
        fi
    done
    if "$HTTPD_BIN" -l 2>/dev/null | grep -Eq 'mod_mpm_(event|worker|prefork)\.c'; then
        return 0
    fi
    return 1
}

port_is_free() {
    requested_port=$1
    "${PYTHON:-python3}" -P - "$requested_port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
}

select_free_port() {
    candidate=$1
    remaining=$2
    while [ "$remaining" -gt 0 ] && [ "$candidate" -lt 65536 ]; do
        if port_is_free "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
        candidate=$((candidate + 1))
        remaining=$((remaining - 1))
    done
    return 1
}

APACHE_MODULES_DIR=$(apache_modules_dir) || \
    blocked "could not determine Apache modules directory from APXS"
PORT=$(select_free_port "$PORT_START" "$PORT_SEARCH_LIMIT") || \
    blocked "no free loopback port from $PORT_START within $PORT_SEARCH_LIMIT attempts"

if [ "$(id -u)" -eq 0 ]; then
    require_command runuser
    require_command chown
    if id -u www-data >/dev/null 2>&1; then
        HTTPD_USER=www-data
    elif id -u nobody >/dev/null 2>&1; then
        HTTPD_USER=nobody
    else
        blocked "root-run Apache needs an unprivileged www-data or nobody user"
    fi
else
    HTTPD_USER=
fi

mkdir -p "$RUNTIME_ROOT/conf" "$RUNTIME_ROOT/htdocs" "$ROOT_LOG_DIR" \
    "$HTTPD_LOG_DIR" "$RUNTIME_ROOT/run" "$RUNTIME_ROOT/modules"
chmod 0711 "$RUNTIME_ROOT"
chmod 0755 "$RUNTIME_ROOT/conf" "$RUNTIME_ROOT/htdocs" "$RUNTIME_ROOT/modules"
# Keep root-owned diagnostics private.  The non-root httpd receives only its
# own error-log and runtime directories after privileged checks finish.
chmod 0711 "$RUNTIME_ROOT/logs"
chmod 0700 "$ROOT_LOG_DIR" "$HTTPD_LOG_DIR" "$RUNTIME_ROOT/run"
: > "$RUNTIME_ROOT/conf/mime.types"
chmod 0644 "$RUNTIME_ROOT/conf/mime.types"
printf 'Apache Autotools smoke control\n' > "$RUNTIME_ROOT/htdocs/index.html"
chmod 0644 "$RUNTIME_ROOT/htdocs/index.html"
mkdir -p "$RUNTIME_ROOT/htdocs${TXID_LENGTH_PREFIX%/}"
printf '127-byte transaction id control\n' > "$RUNTIME_ROOT/htdocs$TXID_127_PATH"
printf '128-byte transaction id must not reach handler\n' > "$RUNTIME_ROOT/htdocs$TXID_128_PATH"
printf 'oversized transaction id must not reach handler\n' > "$RUNTIME_ROOT/htdocs$TXID_LONG_PATH"
chmod 0644 "$RUNTIME_ROOT/htdocs$TXID_127_PATH" \
    "$RUNTIME_ROOT/htdocs$TXID_128_PATH" \
    "$RUNTIME_ROOT/htdocs$TXID_LONG_PATH"
cp "$MODULE_PATH" "$RUNTIME_MODULE_PATH"
chmod 0755 "$RUNTIME_MODULE_PATH"
cmp -s "$MODULE_PATH" "$RUNTIME_MODULE_PATH" || \
    fail "isolated runtime module differs from the Autotools build output"
: > "$HTTPD_ERROR_LOG"
chmod 0600 "$HTTPD_ERROR_LOG"

: > "$MODULES_FILE"
append_mpm_if_needed || blocked "Apache has no loadable or static supported MPM"
append_module_if_present authz_core_module mod_authz_core.so
append_module_if_present authz_host_module mod_authz_host.so
append_module_if_present dir_module mod_dir.so
append_module_if_present mime_module mod_mime.so
chmod 0644 "$MODULES_FILE"

cat > "$CONFIG_FILE" <<EOF
ServerRoot "$RUNTIME_ROOT"
DefaultRuntimeDir "run"
PidFile "run/httpd.pid"
Listen 127.0.0.1:$PORT
ServerName 127.0.0.1
ErrorLog "$HTTPD_ERROR_LOG"
LogLevel warn
TypesConfig "$RUNTIME_ROOT/conf/mime.types"

Include "$MODULES_FILE"
LoadModule security3_module "$RUNTIME_MODULE_PATH"

DocumentRoot "$RUNTIME_ROOT/htdocs"
<Directory "$RUNTIME_ROOT/htdocs">
    Require all granted
</Directory>

modsecurity on
modsecurity_rules "SecRuleEngine On"
modsecurity_rules "SecRule REQUEST_URI \"@streq /blocked\" \"id:100001,phase:1,deny,status:403,log\""
modsecurity_phase4_mode off

<LocationMatch "^/__modsec_txid_length/">
    modsecurity_transaction_id_expr "%{REQUEST_URI}"
</LocationMatch>
EOF
chmod 0644 "$CONFIG_FILE"

if ! "$HTTPD_BIN" -t -f "$CONFIG_FILE" > "$CONFIGTEST_LOG" 2>&1; then
    fail "Apache syntax check failed: $CONFIG_FILE"
fi
grep -F "Syntax OK" "$CONFIGTEST_LOG" >/dev/null || \
    fail "Apache syntax check did not report Syntax OK"
if ! "$HTTPD_BIN" -M -f "$CONFIG_FILE" > "$MODULES_LOG" 2>&1; then
    fail "Apache module listing failed: $CONFIG_FILE"
fi
grep -Eq 'security3_module \(shared\)' "$MODULES_LOG" || \
    fail "Autotools module was not loaded as security3_module"

if [ -n "$HTTPD_USER" ]; then
    chown "$HTTPD_USER" "$RUNTIME_ROOT/run" "$HTTPD_LOG_DIR" "$HTTPD_ERROR_LOG"
fi
chmod 0700 "$RUNTIME_ROOT/run" "$HTTPD_LOG_DIR"
: > "$HTTPD_LOG"
chmod 0600 "$HTTPD_LOG"
exec 3>"$HTTPD_LOG"

if [ -n "$HTTPD_USER" ]; then
    runuser -u "$HTTPD_USER" -- "$HTTPD_BIN" -X -f "$CONFIG_FILE" \
        >&3 2>&3 &
else
    "$HTTPD_BIN" -X -f "$CONFIG_FILE" >&3 2>&3 &
fi
HTTPD_PID=$!

ready=0
attempt=0
while [ "$attempt" -lt 50 ]; do
    if ! kill -0 "$HTTPD_PID" >/dev/null 2>&1; then
        fail "Apache exited before accepting the loopback request"
    fi
    if status=$(curl -s --max-time 2 -o /dev/null -w "$HTTP_STATUS_FORMAT" "http://127.0.0.1:$PORT/index.html") && [ "$status" = 200 ]; then
        ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
[ "$ready" = 1 ] || fail "Apache did not accept an allowed loopback request"

allowed_status=$(curl -sS --max-time 5 -o /dev/null -w "$HTTP_STATUS_FORMAT" "http://127.0.0.1:$PORT/index.html")
[ "$allowed_status" = 200 ] || \
    fail "allowed loopback request returned HTTP $allowed_status instead of 200"
blocked_status=$(curl -sS --max-time 5 -o /dev/null -w "$HTTP_STATUS_FORMAT" "http://127.0.0.1:$PORT/blocked")
[ "$blocked_status" = 403 ] || \
    fail "ModSecurity loopback rule returned HTTP $blocked_status instead of 403"

txid_127_status=$(curl -sS --max-time 5 -o /dev/null -w "$HTTP_STATUS_FORMAT" \
    "http://127.0.0.1:$PORT$TXID_127_PATH")
[ "$txid_127_status" = 200 ] || \
    fail "127-byte transaction identifier control returned HTTP $txid_127_status instead of 200"

TXID_128_HEADERS="$ROOT_LOG_DIR/txid-128.headers"
TXID_128_BODY="$ROOT_LOG_DIR/txid-128.body"
txid_128_status=$(curl -sS --max-time 5 -D "$TXID_128_HEADERS" -o "$TXID_128_BODY" \
    -w "$HTTP_STATUS_FORMAT" "http://127.0.0.1:$PORT$TXID_128_PATH")
[ "$txid_128_status" = 500 ] || \
    fail "128-byte transaction identifier returned HTTP $txid_128_status instead of fail-closed 500"
grep -qi '^Connection: close' "$TXID_128_HEADERS" || \
    fail "128-byte transaction identifier did not close keepalive"
if grep -Fq '128-byte transaction id must not reach handler' "$TXID_128_BODY"; then
    fail "128-byte transaction identifier reached the Apache document handler"
fi

txid_long_status=$(curl -sS --max-time 5 -o /dev/null -w "$HTTP_STATUS_FORMAT" \
    "http://127.0.0.1:$PORT$TXID_LONG_PATH")
[ "$txid_long_status" = 500 ] || \
    fail "oversized transaction identifier returned HTTP $txid_long_status instead of fail-closed 500"

txid_failure_count=$(grep -Fc 'ModSecurity: operation failed: transaction identifier exceeds canonical limit' \
    "$HTTPD_ERROR_LOG" || true)
[ "$txid_failure_count" -eq 2 ] || \
    fail "expected one fail-closed error event per rejected transaction identifier; got $txid_failure_count"

echo "PASS: apache-autotools-bootstrap module=$MODULE_PATH loaded_module=$RUNTIME_MODULE_PATH port=$PORT config=$CONFIG_FILE"
