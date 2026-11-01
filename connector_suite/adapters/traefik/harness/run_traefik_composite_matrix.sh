#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
# Run the real Traefik forwardAuth/local-plugin composite matrix.
#
# This harness is intentionally an orchestration boundary.  It does not
# manufacture matrix results or join events by request id/order/timing.  A
# one trusted case driver must provide exactly one isolated case receipt.  The
# repository verifier validates that receipt against server-generated
# decision_id values; this script never joins a multi-case event stream.
#
# Required environment:
#   RUNTIME_ROOT, COMPOSITE_SOCKET_PARENT, TRAEFIK_BIN, TRAEFIK_VERSION,
#   COMPOSITE_BIN, COMPOSITE_RUNTIME_CONFIG, COMPOSITE_EVENT_LOG,
#   CASE_INPUT, CASE_DRIVER, PYTHON_BIN, UPSTREAM_BIN.
# CASE_DRIVER contract: accept --input, --port, --manifest, --event-log,
# --runtime-root, and --connector; drive exactly one case and create the
# verifier-compatible manifest plus its sibling receipt event log.  The
# driver must obtain the server-generated decision_id from actual observer
# output; this shell runner never constructs it.  UPSTREAM_BIN contract:
# accept --listen, --root, and --case-input and serve the controlled case
# responses, including P3/P4 markers where the case requires them.
#
# CASE_DRIVER and the event/manifest artifacts form one trusted operator
# boundary: this runner verifies their ownership and exact event-log binding,
# but cannot independently prove their provenance.  Its result is therefore
# lifecycle-only; it is not a real-host or rule/vector verdict.
#
# This is intentionally a per-case runner. A complete matrix is produced by
# invoking it once per isolated case/runtime root. P4 Strict is always
# NON_PASS in this runner; a separate host primitive and independent proof are
# required before any external acceptance gate can promote it.
set -eu
LC_ALL=C
export LC_ALL

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}

die() { echo "traefik_composite_matrix: FAIL: $*" >&2; exit 1; }
blocked() { echo "traefik_composite_matrix: BLOCKED: $*" >&2; exit 77; }
need_env() {
    parameter_name=$1
    eval "value=\${$parameter_name-}"
    [ -n "$value" ] || blocked "$parameter_name is required"
}

need_env RUNTIME_ROOT
need_env COMPOSITE_SOCKET_PARENT
need_env TRAEFIK_BIN
need_env COMPOSITE_BIN
need_env COMPOSITE_RUNTIME_CONFIG
need_env COMPOSITE_EVENT_LOG
need_env CASE_INPUT
need_env CASE_DRIVER
need_env PYTHON_BIN
need_env TRAEFIK_VERSION
need_env UPSTREAM_BIN

case "$RUNTIME_ROOT" in /*) ;; *) blocked "RUNTIME_ROOT must be absolute" ;; esac
case "$COMPOSITE_SOCKET_PARENT" in /*) ;; *) blocked "COMPOSITE_SOCKET_PARENT must be absolute" ;; esac
case "$TRAEFIK_BIN" in /*) ;; *) blocked "TRAEFIK_BIN must be absolute" ;; esac
case "$COMPOSITE_BIN" in /*) ;; *) blocked "COMPOSITE_BIN must be absolute" ;; esac
case "$COMPOSITE_RUNTIME_CONFIG" in /*) ;; *) blocked "COMPOSITE_RUNTIME_CONFIG must be absolute" ;; esac
case "$COMPOSITE_EVENT_LOG" in /*) ;; *) blocked "COMPOSITE_EVENT_LOG must be absolute" ;; esac
case "$CASE_INPUT" in /*) ;; *) blocked "CASE_INPUT must be absolute" ;; esac
case "$CASE_DRIVER" in /*) ;; *) blocked "CASE_DRIVER must be absolute" ;; esac
case "$PYTHON_BIN" in /*) ;; *) blocked "PYTHON_BIN must be absolute" ;; esac
case "$UPSTREAM_BIN" in /*) ;; *) blocked "UPSTREAM_BIN must be absolute" ;; esac

is_under() {
    root=$1
    candidate=$2
    case "$candidate" in
        "$root"|"$root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

safe_ancestor_chain() {
    path=$1
    case "$path" in
        *"/../"*|*/..|*"//"*) return 1 ;;
    esac
    current=$path
    while [ "$current" != "/" ]; do
        [ -e "$current" ] && [ ! -L "$current" ] || return 1
        owner=$(stat -c '%u' "$current" 2>/dev/null || echo -1)
        if [ "$current" = "$path" ]; then
            [ "$owner" = "$(id -u)" ] || return 1
        else
            [ "$owner" = "$(id -u)" ] || [ "$owner" = 0 ] || return 1
        fi
        mode_unsafe=$(find "$current" -maxdepth 0 -perm /022 -print -quit 2>/dev/null || true)
        if [ -n "$mode_unsafe" ]; then
            case "$current" in
                /tmp|/var/tmp)
                    [ "$owner" = 0 ] || return 1
                    find "$current" -maxdepth 0 -perm -1000 -print -quit 2>/dev/null | grep -q . || return 1
                    ;;
                *) return 1 ;;
            esac
        fi
        parent=$(dirname "$current")
        [ "$parent" != "$current" ] || break
        current=$parent
    done
    return 0
}

is_private_dir() {
    path=$1
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    safe_ancestor_chain "$path" || return 1
    [ "$(stat -c '%a' "$path" 2>/dev/null || echo -1)" = 700 ] || return 1
    find "$path" -maxdepth 0 -perm /077 -print -quit 2>/dev/null | grep -q . && return 1
    return 0
}

is_owner_file() {
    path=$1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    safe_ancestor_chain "$path" || return 1
    [ "$(stat -c '%u' "$path" 2>/dev/null || echo -1)" = "$(id -u)" ] || return 1
    find "$path" -maxdepth 0 -perm /022 -print -quit 2>/dev/null | grep -q . && return 1
    return 0
}

is_owner_executable() {
    executable_path=$1
    is_owner_file "$executable_path" && [ -x "$executable_path" ]
}

case "$RUNTIME_ROOT" in
    /|/tmp|/var/tmp|"$REPO_ROOT"|"$REPO_ROOT"/*)
        blocked "RUNTIME_ROOT is too broad or inside the checkout: $RUNTIME_ROOT" ;;
    *) : ;;
esac
if [ -e "$RUNTIME_ROOT" ] || [ -L "$RUNTIME_ROOT" ]; then
    is_private_dir "$RUNTIME_ROOT" || blocked "RUNTIME_ROOT must be an owner-only, non-symlink directory"
    find "$RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -print -quit | grep -q . && blocked "RUNTIME_ROOT must be empty"
else
    blocked "RUNTIME_ROOT must pre-exist; this runner will not create it"
fi

# The runtime root is deliberately kept long enough to make artifact ownership
# obvious.  Unix-domain sockets have a much smaller kernel path budget, so the
# caller must explicitly provide a short, private parent for the socket.  Do
# not silently select /tmp or another shared fallback: that would make the
# socket namespace an ambient trust boundary.
case "$COMPOSITE_SOCKET_PARENT" in
    *//*|*/./*|*/../*|*/.|*/..|*/) blocked "COMPOSITE_SOCKET_PARENT must be canonical" ;;
    *[![:print:]]*) blocked "COMPOSITE_SOCKET_PARENT contains control or non-ASCII bytes" ;;
    *) : ;;
esac
case "$COMPOSITE_SOCKET_PARENT" in
    /|/tmp|/var/tmp|/root|/home|/usr|/var|/opt|"$REPO_ROOT"|"$REPO_ROOT"/*)
        blocked "COMPOSITE_SOCKET_PARENT is too broad or inside the checkout: $COMPOSITE_SOCKET_PARENT" ;;
    *) : ;;
esac
[ -d "$COMPOSITE_SOCKET_PARENT" ] && [ ! -L "$COMPOSITE_SOCKET_PARENT" ] || \
    blocked "COMPOSITE_SOCKET_PARENT must be a pre-existing, non-symlink directory"
[ "$(readlink -f -- "$COMPOSITE_SOCKET_PARENT" 2>/dev/null || true)" = "$COMPOSITE_SOCKET_PARENT" ] || \
    blocked "COMPOSITE_SOCKET_PARENT must already be canonical"
is_private_dir "$COMPOSITE_SOCKET_PARENT" || \
    blocked "COMPOSITE_SOCKET_PARENT must be owner-only (0700) and owner-controlled"
SOCKET_PARENT_DEV=$(stat -c '%d' "$COMPOSITE_SOCKET_PARENT" 2>/dev/null || echo -1)
SOCKET_PARENT_INO=$(stat -c '%i' "$COMPOSITE_SOCKET_PARENT" 2>/dev/null || echo -1)
[ "$SOCKET_PARENT_DEV" != -1 ] && [ "$SOCKET_PARENT_INO" != -1 ] || \
    blocked "could not record composite socket parent identity"
revalidate_socket_parent() {
    [ -d "$COMPOSITE_SOCKET_PARENT" ] && [ ! -L "$COMPOSITE_SOCKET_PARENT" ] || return 1
    [ "$(readlink -f -- "$COMPOSITE_SOCKET_PARENT" 2>/dev/null || true)" = "$COMPOSITE_SOCKET_PARENT" ] || return 1
    [ "$(stat -c '%d' "$COMPOSITE_SOCKET_PARENT" 2>/dev/null || echo -1)" = "$SOCKET_PARENT_DEV" ] || return 1
    [ "$(stat -c '%i' "$COMPOSITE_SOCKET_PARENT" 2>/dev/null || echo -1)" = "$SOCKET_PARENT_INO" ] || return 1
    is_private_dir "$COMPOSITE_SOCKET_PARENT"
}
revalidate_socket_parent || blocked "composite socket parent changed before child creation"

SOCKET_CHILD=
SOCKET_CHILD_DEV=
SOCKET_CHILD_INO=
SOCKET_BASENAME=composite.sock
cleanup_socket_child() {
    set +e
    [ -n "$SOCKET_CHILD" ] || return 0
    if [ -n "$SOCKET_CHILD_DEV" ] && [ -n "$SOCKET_CHILD_INO" ] &&
        [ -d "$SOCKET_CHILD" ] && [ ! -L "$SOCKET_CHILD" ] &&
        [ "$(stat -c '%d' "$SOCKET_CHILD" 2>/dev/null || echo -1)" = "$SOCKET_CHILD_DEV" ] &&
        [ "$(stat -c '%i' "$SOCKET_CHILD" 2>/dev/null || echo -1)" = "$SOCKET_CHILD_INO" ]; then
        if ! rmdir -- "$SOCKET_CHILD" 2>/dev/null; then
            echo "traefik_composite_matrix: cleanup failed for exact socket child $SOCKET_CHILD" >&2
            return 1
        fi
    else
        echo "traefik_composite_matrix: socket child identity changed or unavailable; refusing cleanup $SOCKET_CHILD" >&2
        return 1
    fi
}
SOCKET_CHILD=$(mktemp -d -- "$COMPOSITE_SOCKET_PARENT/.traefik-composite.XXXXXX") || \
    blocked "failed to create private composite socket child"
SOCKET_CHILD_DEV=$(stat -c '%d' "$SOCKET_CHILD" 2>/dev/null || echo -1)
SOCKET_CHILD_INO=$(stat -c '%i' "$SOCKET_CHILD" 2>/dev/null || echo -1)
[ "$SOCKET_CHILD_DEV" != -1 ] && [ "$SOCKET_CHILD_INO" != -1 ] || \
    blocked "could not record composite socket child identity"
trap cleanup_socket_child EXIT
chmod 700 "$SOCKET_CHILD" || blocked "failed to restrict composite socket child"
[ "$(readlink -f -- "$SOCKET_CHILD" 2>/dev/null || true)" = "$SOCKET_CHILD" ] || \
    blocked "created composite socket child is not canonical"
is_private_dir "$SOCKET_CHILD" || blocked "created composite socket child is unsafe"
revalidate_socket_parent || blocked "composite socket parent changed after child creation"
COMPOSITE_SOCKET="$SOCKET_CHILD/$SOCKET_BASENAME"
case "$COMPOSITE_SOCKET" in
    *[![:print:]]*) blocked "COMPOSITE_SOCKET contains control or non-ASCII bytes" ;;
    *) : ;;
esac
[ "$(LC_ALL=C expr length "$COMPOSITE_SOCKET")" -le 100 ] || \
    blocked "COMPOSITE_SOCKET leaves no safe Unix-socket path budget"
[ ! -e "$COMPOSITE_SOCKET" ] && [ ! -L "$COMPOSITE_SOCKET" ] || blocked "COMPOSITE_SOCKET already exists"

is_owner_executable "$TRAEFIK_BIN" || blocked "TRAEFIK_BIN must be an owner-controlled executable"
is_owner_executable "$COMPOSITE_BIN" || blocked "COMPOSITE_BIN must be an owner-controlled executable"
is_owner_executable "$CASE_DRIVER" || blocked "CASE_DRIVER must be an owner-controlled executable"
is_owner_executable "$PYTHON_BIN" || blocked "PYTHON_BIN must be an owner-controlled executable"
is_owner_executable "$UPSTREAM_BIN" || blocked "UPSTREAM_BIN must be an owner-controlled executable"
is_owner_file "$COMPOSITE_RUNTIME_CONFIG" || blocked "COMPOSITE_RUNTIME_CONFIG must be an owner-controlled regular file"
is_owner_file "$CASE_INPUT" || blocked "CASE_INPUT must be an owner-controlled regular file"
find "$COMPOSITE_RUNTIME_CONFIG" -maxdepth 0 -perm /077 -print -quit 2>/dev/null | grep -q . && \
    blocked "COMPOSITE_RUNTIME_CONFIG must not be group/world writable"
case "$COMPOSITE_RUNTIME_CONFIG" in
    "$REPO_ROOT"|"$REPO_ROOT"/*) blocked "COMPOSITE_RUNTIME_CONFIG must be outside the checkout" ;;
    *) : ;;
esac
if [ -e "$COMPOSITE_EVENT_LOG" ] || [ -L "$COMPOSITE_EVENT_LOG" ]; then
    blocked "COMPOSITE_EVENT_LOG must not already exist"
fi
case "$(dirname "$COMPOSITE_EVENT_LOG")" in
    "$RUNTIME_ROOT") : ;;
    *) blocked "COMPOSITE_EVENT_LOG must be directly below RUNTIME_ROOT" ;;
esac
safe_direct_child() {
    root=$1
    child=$2
    case "$child" in
        "$root"/*) ;;
        *) return 1 ;;
    esac
    case "$child" in
        *//*|*/./*|*/../*|*/.|*/..|*/) return 1 ;;
        *) : ;;
    esac
    [ "$(dirname "$child")" = "$root" ] || return 1
    base=$(basename "$child")
    [ -n "$base" ] && [ "$base" != "." ] && [ "$base" != ".." ]
}
safe_direct_child "$RUNTIME_ROOT" "$COMPOSITE_EVENT_LOG" || \
    blocked "COMPOSITE_EVENT_LOG must be a safe direct child of RUNTIME_ROOT"
CASE_MANIFEST="$RUNTIME_ROOT/case.manifest.json"
CASE_INPUT_COPY="$RUNTIME_ROOT/case-input.json"
safe_direct_child "$RUNTIME_ROOT" "$CASE_MANIFEST" || blocked "CASE_MANIFEST must be a safe direct child of RUNTIME_ROOT"
safe_direct_child "$RUNTIME_ROOT" "$CASE_INPUT_COPY" || blocked "CASE_INPUT_COPY must be a safe direct child of RUNTIME_ROOT"
[ ! -e "$CASE_MANIFEST" ] && [ ! -L "$CASE_MANIFEST" ] || blocked "CASE_MANIFEST already exists"
[ ! -e "$CASE_INPUT_COPY" ] && [ ! -L "$CASE_INPUT_COPY" ] || blocked "CASE_INPUT_COPY already exists"
UPSTREAM_OBSERVATION="$RUNTIME_ROOT/upstream-observation.json"
safe_direct_child "$RUNTIME_ROOT" "$UPSTREAM_OBSERVATION" || \
    blocked "UPSTREAM_OBSERVATION must be a safe direct child of RUNTIME_ROOT"
[ ! -e "$UPSTREAM_OBSERVATION" ] && [ ! -L "$UPSTREAM_OBSERVATION" ] || \
    blocked "UPSTREAM_OBSERVATION already exists"
UPSTREAM_CERTIFICATE="$RUNTIME_ROOT/upstream-cert.pem"
UPSTREAM_KEY="$RUNTIME_ROOT/upstream-key.pem"
safe_direct_child "$RUNTIME_ROOT" "$UPSTREAM_CERTIFICATE" || blocked "UPSTREAM_CERTIFICATE must be a safe direct child of RUNTIME_ROOT"
safe_direct_child "$RUNTIME_ROOT" "$UPSTREAM_KEY" || blocked "UPSTREAM_KEY must be a safe direct child of RUNTIME_ROOT"
[ ! -e "$UPSTREAM_CERTIFICATE" ] && [ ! -L "$UPSTREAM_CERTIFICATE" ] || blocked "UPSTREAM_CERTIFICATE already exists"
[ ! -e "$UPSTREAM_KEY" ] && [ ! -L "$UPSTREAM_KEY" ] || blocked "UPSTREAM_KEY already exists"

case "$TRAEFIK_VERSION" in ''|*[!0-9.]*) blocked "TRAEFIK_VERSION must be a dotted numeric pin" ;; *) : ;; esac
version_text=$("$TRAEFIK_BIN" version 2>&1 || true)
printf '%s\n' "$version_text" | grep -Eq "(^|[^0-9.])$TRAEFIK_VERSION([^0-9.]|$)" || \
    blocked "TRAEFIK_BIN version output does not match explicit TRAEFIK_VERSION=$TRAEFIK_VERSION"

PLUGIN_SOURCE="$REPO_ROOT/connectors/traefik/composite_middleware"
STATIC_TEMPLATE="$REPO_ROOT/connectors/traefik/config/traefik-forwardauth-composite-static.yaml"
DYNAMIC_TEMPLATE="$REPO_ROOT/connectors/traefik/config/traefik-forwardauth-composite-dynamic.yaml"
[ -d "$PLUGIN_SOURCE" ] && [ ! -L "$PLUGIN_SOURCE" ] || blocked "composite plugin source is missing or symlinked"
is_owner_file "$STATIC_TEMPLATE" || blocked "static composite template is missing or unsafe"
is_owner_file "$DYNAMIC_TEMPLATE" || blocked "dynamic composite template is missing or unsafe"
find -L "$PLUGIN_SOURCE" -type l -print -quit | grep -q . && blocked "plugin source contains symlinks"

PLUGIN_ROOT="$RUNTIME_ROOT/plugins-local/src/github.com/Easton97-Jens/ModSecurity-conector/connectors/traefik/composite_middleware"
CONFIG_ROOT="$RUNTIME_ROOT/effective-config"
UPSTREAM_ROOT="$RUNTIME_ROOT/upstream"
LOG_ROOT="$RUNTIME_ROOT/process-logs"
DYNAMIC_CONFIG="$CONFIG_ROOT/traefik-forwardauth-composite-dynamic.yaml"
STATIC_CONFIG="$CONFIG_ROOT/traefik-forwardauth-composite-static.yaml"
case "$RUNTIME_ROOT" in
    uds_unavailable|*-uds_unavailable|*-uds_unavailable-*)
        blocked "uds_unavailable is pre-admission transport failure and cannot produce correlated composite evidence"
        ;;
    *) : ;;
esac
mkdir -p "$PLUGIN_ROOT" "$CONFIG_ROOT" "$UPSTREAM_ROOT" "$LOG_ROOT"
chmod 700 "$CONFIG_ROOT" "$UPSTREAM_ROOT" "$LOG_ROOT"
umask 077
cp -- "$CASE_INPUT" "$CASE_INPUT_COPY" || blocked "failed to copy CASE_INPUT into private runtime root"
chmod 600 "$CASE_INPUT_COPY"
if [ "$(stat -c '%s' "$CASE_INPUT_COPY" 2>/dev/null || echo 0)" -gt 256000 ]; then
    blocked "CASE_INPUT exceeds the bounded catalog size"
fi
# The selected case is an explicit field in the bounded catalog. It is used
# for the one case-specific transport/configuration exception below; runtime
# directory names are never a behavioral input.
SELECTED_CASE=$(
    "$PYTHON_BIN" - "$CASE_INPUT_COPY" <<'PY'
import json
import sys

cases = {
    "p1_allow", "p1_deny", "p2_allow", "p2_deny", "p2_oversize",
    "p3_deny", "p3_redirect", "p4_safe", "p4_strict",
    "metadata_omitted", "p2_to_p3_timeout",
}
with open(sys.argv[1], "rb") as handle:
    catalog = json.load(handle)
selected = catalog.get("selected_case") if isinstance(catalog, dict) else None
if not isinstance(selected, str) or selected not in cases:
    raise SystemExit(1)
print(selected)
PY
) || blocked "CASE_INPUT must contain one supported selected_case"
: > "$UPSTREAM_OBSERVATION"
chmod 600 "$UPSTREAM_OBSERVATION"
cp -R --no-preserve=ownership,mode "$PLUGIN_SOURCE"/. "$PLUGIN_ROOT"/ || die "failed to stage local plugin"

AUTH_PORT=${AUTH_PORT:-19182}
TRAEFIK_PORT=${TRAEFIK_PORT:-19180}
UPSTREAM_PORT=${UPSTREAM_PORT:-19181}
case "$AUTH_PORT:$TRAEFIK_PORT:$UPSTREAM_PORT" in *[!0-9:]*|*:*:*:*) blocked "ports must be decimal" ;; *) : ;; esac

escape_sed() {
    value=$1
    printf '%s' "$value" | sed 's/[\\&|]/\\&/g'
}
AUTH_ADDRESS="127.0.0.1:$AUTH_PORT"
TRAEFIK_ADDRESS="127.0.0.1:$TRAEFIK_PORT"
UPSTREAM_ADDRESS="127.0.0.1:$UPSTREAM_PORT"
SOCKET_ESC=$(escape_sed "$COMPOSITE_SOCKET")
AUTH_ESC=$(escape_sed "$AUTH_ADDRESS")
TRAEFIK_ESC=$(escape_sed "$TRAEFIK_ADDRESS")
UPSTREAM_ESC=$(escape_sed "$UPSTREAM_ADDRESS")
DYNAMIC_CONFIG_ESC=$(escape_sed "$DYNAMIC_CONFIG")
OPENSSL_BIN=$(command -v openssl 2>/dev/null || true)
case "$OPENSSL_BIN" in /*) ;; *) blocked "openssl is required to generate the ephemeral upstream TLS certificate" ;; esac
is_owner_executable "$OPENSSL_BIN" || blocked "openssl is not an owner-controlled executable"
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -keyout "$UPSTREAM_KEY" -out "$UPSTREAM_CERTIFICATE" \
    -subj "/CN=composite-upstream.local" \
    -addext "subjectAltName=DNS:composite-upstream.local" \
    >/dev/null 2>&1 || blocked "failed to generate the ephemeral upstream TLS certificate"
chmod 600 "$UPSTREAM_CERTIFICATE" "$UPSTREAM_KEY"
is_owner_file "$UPSTREAM_CERTIFICATE" || blocked "generated upstream certificate is unsafe"
is_owner_file "$UPSTREAM_KEY" || blocked "generated upstream key is unsafe"
UPSTREAM_CERT_ESC=$(escape_sed "$UPSTREAM_CERTIFICATE")
sed -e "s|__AUTH_ADDRESS__|$AUTH_ESC|g" -e "s|__COMPOSITE_SOCKET__|$SOCKET_ESC|g" -e "s|__UPSTREAM_ADDRESS__|$UPSTREAM_ESC|g" \
    -e "s|__UPSTREAM_CERTIFICATE__|$UPSTREAM_CERT_ESC|g" "$DYNAMIC_TEMPLATE" > "$DYNAMIC_CONFIG"
# This negative case removes only the private lease from the explicit
# ForwardAuth request allow-list. The outer plugin still reserves privately,
# but ForwardAuth receives no lease and fails closed before P1/P2; the UDS
# disconnect aborts that reservation without creating false phase evidence.
case "$SELECTED_CASE" in
    metadata_omitted)
        sed -i '/^[[:space:]]*-[[:space:]]*X-Msconnector-Composite-Lease[[:space:]]*$/d' "$DYNAMIC_CONFIG"
        ;;
    *) : ;;
esac
sed -e "s|__TRAEFIK_ADDRESS__|$TRAEFIK_ESC|g" -e "s|__TRAEFIK_DYNAMIC_CONFIG__|$DYNAMIC_CONFIG_ESC|g" \
    "$STATIC_TEMPLATE" > "$STATIC_CONFIG"
printf 'composite upstream controlled response\n' > "$UPSTREAM_ROOT/index.html"
chmod 600 "$CONFIG_ROOT"/* "$UPSTREAM_ROOT/index.html"

pid_start_token() {
    pid=$1
    sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | awk '{print $20}'
}
pid_is_owned() {
    pid=$1
    exe_path=$2
    expected_start=$3
    [ -d "/proc/$pid" ] || return 1
    [ "$(stat -c '%u' "/proc/$pid" 2>/dev/null || echo -1)" = "$(id -u)" ] || return 1
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    [ "$exe" = "$exe_path" ] || return 1
    actual_start=$(pid_start_token "$pid")
    [ -n "$actual_start" ] && [ "$actual_start" = "$expected_start" ]
}
pid_is_owned_upstream() {
    pid=$1
    expected_start=$2
    [ -d "/proc/$pid" ] || return 1
    [ "$(stat -c '%u' "/proc/$pid" 2>/dev/null || echo -1)" = "$(id -u)" ] || return 1
    actual_start=$(pid_start_token "$pid")
    [ -n "$actual_start" ] && [ "$actual_start" = "$expected_start" ] &&
        kill -0 "$pid" 2>/dev/null
}
wait_pid() {
    pid=$1
    limit=$2
    exe_path=$3
    expected_start=$4
    i=0
    while [ "$i" -lt "$limit" ]; do
        pid_is_owned "$pid" "$exe_path" "$expected_start" && kill -0 "$pid" 2>/dev/null && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}
wait_tcp() {
    port=$1
    limit=$2
    pid=$3
    exe=$4
    expected_start=$5
    kind=$6
    i=0
    while [ "$i" -lt "$limit" ]; do
        if "$PYTHON_BIN" -c 'import socket,sys; s=socket.create_connection(("127.0.0.1", int(sys.argv[1])), 2); s.close()' "$port" >/dev/null 2>&1; then
            return 0
        fi
        if [ "$kind" = upstream ]; then
            pid_is_owned_upstream "$pid" "$expected_start" || return 1
        else
            pid_is_owned "$pid" "$exe" "$expected_start" || return 1
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}
stop_owned() {
    pid=$1
    exe=$2
    expected_start=$3
    if pid_is_owned "$pid" "$exe" "$expected_start"; then
        kill -TERM "$pid" 2>/dev/null || true
        i=0
        while [ "$i" -lt 10 ]; do
            pid_is_owned "$pid" "$exe" "$expected_start" || break
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
            i=$((i + 1))
        done
        pid_is_owned "$pid" "$exe" "$expected_start" && kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}
stop_owned_upstream() {
    pid=$1
    expected_start=$2
    if pid_is_owned_upstream "$pid" "$expected_start"; then
        kill -TERM "$pid" 2>/dev/null || true
        i=0
        while [ "$i" -lt 10 ]; do
            pid_is_owned_upstream "$pid" "$expected_start" || break
            sleep 1
            i=$((i + 1))
        done
        pid_is_owned_upstream "$pid" "$expected_start" && kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

UPSTREAM_PID=
UPSTREAM_START=
COMPOSITE_PID=
COMPOSITE_START=
TRAEFIK_PID=
TRAEFIK_START=
cleanup() {
    set +e
    [ -n "$TRAEFIK_PID" ] && stop_owned "$TRAEFIK_PID" "$TRAEFIK_BIN" "$TRAEFIK_START"
    [ -n "$COMPOSITE_PID" ] && stop_owned "$COMPOSITE_PID" "$COMPOSITE_BIN" "$COMPOSITE_START"
    [ -n "$UPSTREAM_PID" ] && stop_owned_upstream "$UPSTREAM_PID" "$UPSTREAM_START"
    cleanup_socket_child
}
on_signal() {
    code=$1
    cleanup
    trap - EXIT INT TERM
    exit "$code"
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

# The helper selects a fixed six-second response-header delay only from the
# exact owner-controlled runtime-root case suffix; CASE_INPUT cannot activate
# transport timing behavior.
"$UPSTREAM_BIN" --listen "127.0.0.1:$UPSTREAM_PORT" --root "$RUNTIME_ROOT" --case-input "$CASE_INPUT_COPY" \
    --observation "$UPSTREAM_OBSERVATION" --observation-root "$RUNTIME_ROOT" \
    --cert "$UPSTREAM_CERTIFICATE" --key "$UPSTREAM_KEY" >"$LOG_ROOT/upstream.log" 2>&1 &
UPSTREAM_PID=$!
UPSTREAM_START=$(pid_start_token "$UPSTREAM_PID")
pid_is_owned_upstream "$UPSTREAM_PID" "$UPSTREAM_START" || die "controlled upstream failed to start"
wait_tcp "$UPSTREAM_PORT" 10 "$UPSTREAM_PID" "$UPSTREAM_BIN" "$UPSTREAM_START" upstream || \
    die "controlled upstream TCP readiness timeout"

"$COMPOSITE_BIN" --mode traefik --forwardauth-listen "$AUTH_ADDRESS" --uds "$COMPOSITE_SOCKET" --runtime-config "$COMPOSITE_RUNTIME_CONFIG" --event-log "$COMPOSITE_EVENT_LOG" >"$LOG_ROOT/composite.log" 2>&1 &
COMPOSITE_PID=$!
COMPOSITE_START=$(sed 's/.*) //' "/proc/$COMPOSITE_PID/stat" 2>/dev/null | awk '{print $20}')
wait_pid "$COMPOSITE_PID" 3 "$COMPOSITE_BIN" "$COMPOSITE_START" || die "composite service failed to start"
wait_tcp "$AUTH_PORT" 10 "$COMPOSITE_PID" "$COMPOSITE_BIN" "$COMPOSITE_START" composite || \
    die "composite ForwardAuth TCP readiness timeout"

cd "$RUNTIME_ROOT"
"$TRAEFIK_BIN" --configFile="$STATIC_CONFIG" \
    --log.level=INFO >"$LOG_ROOT/traefik.log" 2>&1 &
TRAEFIK_PID=$!
TRAEFIK_START=$(sed 's/.*) //' "/proc/$TRAEFIK_PID/stat" 2>/dev/null | awk '{print $20}')
wait_pid "$TRAEFIK_PID" 5 "$TRAEFIK_BIN" "$TRAEFIK_START" || die "Traefik failed to start"

wait_tcp "$TRAEFIK_PORT" 20 "$TRAEFIK_PID" "$TRAEFIK_BIN" "$TRAEFIK_START" traefik || \
    die "Traefik TCP readiness timeout"
# The static listener binds before the file provider has atomically installed
# the dynamic router/middleware chain.  Keep the activation interval bounded
# so the case driver cannot accidentally test Traefik's transient 404 route.
sleep 1

# CASE_DRIVER owns request/response traffic for exactly one case.  It must
# create CASE_MANIFEST and its sibling receipt event log; it must not put an expected
# decision_id in the manifest.  This runner does not synthesize event fields
# or correlate by request id, URI, address, order, or timing.
"$CASE_DRIVER" --input "$CASE_INPUT_COPY" --port "$TRAEFIK_PORT" \
    --manifest "$CASE_MANIFEST" --event-log "$COMPOSITE_EVENT_LOG" \
    --runtime-root "$RUNTIME_ROOT" --upstream-observation "$UPSTREAM_OBSERVATION" --connector traefik

VERIFIER_SCRIPT="$TEST_ROOT/connector_suite/adapters/composite_harness/verify_matrix_evidence.py"
is_owner_file "$VERIFIER_SCRIPT" || die "shared composite verifier is missing or unsafe"
[ -f "$COMPOSITE_EVENT_LOG" ] && [ ! -L "$COMPOSITE_EVENT_LOG" ] || die "composite service produced no safe raw event log"
is_owner_file "$COMPOSITE_EVENT_LOG" || die "composite raw event log is not owner-controlled"
[ -f "$CASE_MANIFEST" ] && [ ! -L "$CASE_MANIFEST" ] || die "case driver produced no safe manifest"
# The verifier output is lifecycle-only evidence. P4 Strict is always
# non-promoting here; a driver assertion cannot establish a real client-visible
# host reset or abort.
"$PYTHON_BIN" "$VERIFIER_SCRIPT" "$CASE_MANIFEST" --expected-event-log "$COMPOSITE_EVENT_LOG" --runtime-root "$RUNTIME_ROOT" --json >"$RUNTIME_ROOT/lifecycle-verification.json"
chmod 600 "$RUNTIME_ROOT/lifecycle-verification.json"
