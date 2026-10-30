#!/bin/sh
# Resolve test infrastructure only from the explicitly selected Framework.
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
: "${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}"
: "${CONNECTOR_REVISION:?CONNECTOR_REVISION is required explicitly}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$TEST_ROOT/ci/lib/path-bootstrap.sh"
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
VERIFIED_RUN_ROOT="${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}"
VERIFIED_BUILD_ROOT="${VERIFIED_BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}"
BUILD_ROOT="${BUILD_ROOT:-$VERIFIED_BUILD_ROOT}"
APACHE_BUILD_ROOT="${APACHE_BUILD_ROOT:-$BUILD_ROOT/apache-build}"
HTTPD_PREFIX="${HTTPD_PREFIX:-$BUILD_ROOT/apache-runtime/httpd}"
APACHE_MODULE="${APACHE_MODULE:-$APACHE_BUILD_ROOT/output/apache/mod_security3.so}"
MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-$APACHE_BUILD_ROOT/output/modsecurity/lib}"
MODSECURITY_V3_DIR="${MODSECURITY_V3_DIR:-$APACHE_BUILD_ROOT/ModSecurity_V3}"
PCRE2_PREFIX="${PCRE2_PREFIX:-$APACHE_BUILD_ROOT/output/pcre2}"
APACHE_HTTPD_BIN="${APACHE_HTTPD_BIN:-${APACHE_HTTPD:-${APACHE:-$HTTPD_PREFIX/bin/httpd}}}"
APXS_BIN="${APXS_BIN:-${APXS:-$HTTPD_PREFIX/bin/apxs}}"
RUNTIME_ROOT="${RUNTIME_ROOT:-$BUILD_ROOT/apache-directive-config-check}"
LOG_DIR="${LOG_DIR:-$BUILD_ROOT/logs/apache-directive-config}"
PORT="${APACHE_DIRECTIVE_CONFIG_PORT:-18180}"
CURL_BIN="${CURL:-$(command -v curl 2>/dev/null || true)}"
CONFIG_FILE="$RUNTIME_ROOT/conf/httpd.conf"
MODULES_FILE="$RUNTIME_ROOT/conf/modules.load"
CONFIGTEST_LOG="$LOG_DIR/configtest.log"
SERVER_LOG="$LOG_DIR/server.log"
IFMODULE_END="</IfModule>"

blocked() {
    echo "apache_directive_config: blocked $*" >&2
    exit 77
}

fail() {
    echo "apache_directive_config: fail $*" >&2
    if [ -f "$CONFIGTEST_LOG" ]; then
        echo "apache_directive_config: configtest log follows" >&2
        sed -n '1,160p' "$CONFIGTEST_LOG" >&2
    fi
    exit 1
}

cleanup() {
    if [ -f "$RUNTIME_ROOT/logs/httpd.pid" ]; then
        "$APACHE_HTTPD_BIN" -f "$CONFIG_FILE" -k stop >/dev/null 2>&1 || true
    fi
}

require_absolute_generated_path() {
    path=$1
    label=$2
    case "$path" in
        /*) ;;
        *) blocked "$label must be absolute: $path" ;;
    esac
    case "$path" in
        "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*|"$FRAMEWORK_ROOT"|"$FRAMEWORK_ROOT"/*)
            blocked "$label must not be inside the source checkout: $path"
            ;;
        *) ;;
    esac
}

apache_modules_dir() {
    if [ -n "$APXS_BIN" ] && [ -x "$APXS_BIN" ]; then
        dir=$("$APXS_BIN" -q LIBEXECDIR 2>/dev/null || true)
        if [ -n "$dir" ]; then
            printf '%s\n' "$dir"
            return 0
        fi
        libdir=$("$APXS_BIN" -q LIBDIR 2>/dev/null || true)
        if [ -n "$libdir" ]; then
            printf '%s/modules\n' "$libdir"
            return 0
        fi
    fi
    if [ -d "$HTTPD_PREFIX/modules" ]; then
        printf '%s\n' "$HTTPD_PREFIX/modules"
        return 0
    fi
    return 1
}

append_load_if_exists() {
    module_name=$1
    file_name=$2
    modules_dir=$3
    output=$4
    module_path="$modules_dir/$file_name"
    if [ -f "$module_path" ]; then
        {
            echo "<IfModule !$module_name>"
            echo "LoadModule $module_name \"$module_path\""
            echo "$IFMODULE_END"
        } >> "$output"
    fi
}

append_mpm_if_needed() {
    modules_dir=$1
    output=$2
    for candidate in \
        "mpm_event_module mod_mpm_event.so" \
        "mpm_worker_module mod_mpm_worker.so" \
        "mpm_prefork_module mod_mpm_prefork.so"
    do
        module_name=${candidate% *}
        file_name=${candidate#* }
        module_path="$modules_dir/$file_name"
        if [ -f "$module_path" ]; then
            {
                echo "<IfModule !mpm_event_module>"
                echo "<IfModule !mpm_worker_module>"
                echo "<IfModule !mpm_prefork_module>"
                echo "LoadModule $module_name \"$module_path\""
                echo "$IFMODULE_END"
                echo "$IFMODULE_END"
                echo "$IFMODULE_END"
            } >> "$output"
            return 0
        fi
    done
    return 1
}

write_modules_file() {
    modules_dir=$1
    : > "$MODULES_FILE"
    append_mpm_if_needed "$modules_dir" "$MODULES_FILE" || \
        blocked "missing Apache MPM module under $modules_dir"
    append_load_if_exists "authz_core_module" "mod_authz_core.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "authz_host_module" "mod_authz_host.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "unixd_module" "mod_unixd.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "dir_module" "mod_dir.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "mime_module" "mod_mime.so" "$modules_dir" "$MODULES_FILE"
    append_load_if_exists "remoteip_module" "mod_remoteip.so" "$modules_dir" "$MODULES_FILE"
}

write_documents() {
    printf '%s\n' "blocked path" > "$RUNTIME_ROOT/htdocs/__modsec_directive_block"
    printf '%s\n' "off path" > "$RUNTIME_ROOT/htdocs/__modsec_directive_off"
    printf '%s\n' "remoteip path" > "$RUNTIME_ROOT/htdocs/__modsec_remoteip"
    printf '%s\n' "transaction id expression path" > "$RUNTIME_ROOT/htdocs/__modsec_txid_expr"
}

write_config() {
    cat > "$CONFIG_FILE" <<EOF
ServerRoot "$RUNTIME_ROOT"
PidFile "logs/httpd.pid"
Listen 127.0.0.1:$PORT
ServerName 127.0.0.1
DefaultRuntimeDir "run"
ErrorLog "logs/error.log"
LogLevel debug

Include "$MODULES_FILE"
LoadModule security3_module "$APACHE_MODULE"

DocumentRoot "$RUNTIME_ROOT/htdocs"
<Directory "$RUNTIME_ROOT/htdocs">
    Require all granted
</Directory>

<IfModule remoteip_module>
    RemoteIPHeader X-Forwarded-For
</IfModule>

modsecurity on
modsecurity_use_error_log off
modsecurity_transaction_id static-test-id
modsecurity_rules "SecRuleEngine On"
modsecurity_rules "SecRule REQUEST_URI \"__modsec_directive\" \"id:900001,phase:1,deny,status:403\""
modsecurity_rules "SecRule REMOTE_ADDR \"@ipMatch 1.2.3.4\" \"id:900002,phase:1,deny,status:406\""
modsecurity_rules "SecRule UNIQUE_ID \"@streq /__modsec_txid_expr\" \"id:900003,phase:1,deny,status:409\""

<Location "/__modsec_directive_config_parse">
    modsecurity_use_error_log on
</Location>

<Location "/__modsec_directive_off">
    modsecurity off
</Location>

<Location "/__modsec_txid_expr">
    modsecurity_transaction_id_expr "%{REQUEST_URI}"
</Location>
EOF
}

start_server() {
    "$APACHE_HTTPD_BIN" -f "$CONFIG_FILE" -k start > "$SERVER_LOG" 2>&1 || \
        fail "Apache start failed"

    i=0
    while [ "$i" -lt 50 ]; do
        if "$CURL_BIN" -sS -o /dev/null "http://127.0.0.1:$PORT/__modsec_directive_off" >/dev/null 2>&1; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done

    fail "Apache did not become ready"
}

request_status() {
    path=$1
    "$CURL_BIN" -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT$path"
}

request_status_with_forwarded_for() {
    path=$1
    "$CURL_BIN" -sS -o /dev/null -w "%{http_code}" \
        -H "X-Forwarded-For: 1.2.3.4" "http://127.0.0.1:$PORT$path"
}

require_absolute_generated_path "$BUILD_ROOT" "BUILD_ROOT"
require_absolute_generated_path "$RUNTIME_ROOT" "RUNTIME_ROOT"
require_absolute_generated_path "$LOG_DIR" "LOG_DIR"

case "$RUNTIME_ROOT" in
    "$BUILD_ROOT"/*) ;;
    *) blocked "RUNTIME_ROOT must be inside BUILD_ROOT: $RUNTIME_ROOT" ;;
esac
case "$RUNTIME_ROOT" in
    "$BUILD_ROOT"|"$BUILD_ROOT/"|/) blocked "unsafe RUNTIME_ROOT: $RUNTIME_ROOT" ;;
    *) ;;
esac

[ -x "$APACHE_HTTPD_BIN" ] || blocked "missing Apache httpd executable: $APACHE_HTTPD_BIN"
[ -f "$APACHE_MODULE" ] || blocked "missing Apache connector module: $APACHE_MODULE"
[ -n "$CURL_BIN" ] || blocked "missing curl; set CURL=/path/to/curl"
[ -x "$CURL_BIN" ] || blocked "curl is not executable: $CURL_BIN"

if [ ! -f "$MODSECURITY_LIB_DIR/libmodsecurity.so" ]; then
    if [ -f "$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so" ]; then
        MODSECURITY_LIB_DIR="$MODSECURITY_V3_DIR/src/.libs"
    else
        blocked "missing libmodsecurity.so under $MODSECURITY_LIB_DIR"
    fi
fi

modules_dir=$(apache_modules_dir) || blocked "missing Apache modules directory"
if [ -f "$modules_dir/mod_remoteip.so" ]; then
    remoteip_available=1
else
    remoteip_available=0
fi

rm -rf "$RUNTIME_ROOT"
mkdir -p "$RUNTIME_ROOT/conf" "$RUNTIME_ROOT/logs" "$RUNTIME_ROOT/run" \
    "$RUNTIME_ROOT/htdocs" "$LOG_DIR"
: > "$RUNTIME_ROOT/conf/mime.types"

write_modules_file "$modules_dir"
write_documents
write_config

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR:$HTTPD_PREFIX/lib:$PCRE2_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH

if ! "$APACHE_HTTPD_BIN" -t -f "$CONFIG_FILE" > "$CONFIGTEST_LOG" 2>&1; then
    fail "Apache config parse failed"
fi

if ! grep -q "Syntax OK" "$CONFIGTEST_LOG"; then
    fail "Apache config parse did not report Syntax OK"
fi

trap cleanup EXIT INT TERM
start_server

blocked_status=$(request_status "/__modsec_directive_block")
if [ "$blocked_status" != "403" ]; then
    fail "expected global modsecurity on request to be blocked with 403; got $blocked_status"
fi

off_status=$(request_status "/__modsec_directive_off")
if [ "$off_status" != "200" ]; then
    fail "expected Location modsecurity off request to bypass ModSecurity and return 200; got $off_status"
fi

txid_expr_status=$(request_status "/__modsec_txid_expr")
if [ "$txid_expr_status" != "409" ]; then
    fail "expected modsecurity_transaction_id_expr to evaluate REQUEST_URI and block with 409; got $txid_expr_status"
fi

if [ "$remoteip_available" = "1" ]; then
    remoteip_control_status=$(request_status "/__modsec_remoteip")
    if [ "$remoteip_control_status" != "200" ]; then
        fail "expected RemoteIP control request without X-Forwarded-For to return 200; got $remoteip_control_status"
    fi

    remoteip_status=$(request_status_with_forwarded_for "/__modsec_remoteip")
    if [ "$remoteip_status" != "406" ]; then
        fail "expected RemoteIPHeader request to set REMOTE_ADDR and block with 406; got $remoteip_status"
    fi
else
    echo "apache_directive_config: skip RemoteIPHeader runtime check; mod_remoteip.so not found under $modules_dir"
fi

echo "apache_directive_config: pass Syntax OK and runtime gate config=$CONFIG_FILE log=$CONFIGTEST_LOG"
