#!/bin/sh
set -eu

: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
REPO_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
CONNECTOR_DIR="$REPO_ROOT/connectors/traefik"
BUILD_ROOT="${BUILD_ROOT:-${TMPDIR:-/var/tmp}/ModSecurity-conector-verified/build}"
COMPONENT_CACHE="${CONNECTOR_COMPONENT_CACHE:-${TMPDIR:-/var/tmp}/ModSecurity-conector-verified/cache-v2/shared}"
CONNECTOR_BIN="${TRAEFIK_CONNECTOR_BIN:-$BUILD_ROOT/traefik-connector/traefik-forwardauth}"
TRAEFIK_BIN="${TRAEFIK_BIN:-$COMPONENT_CACHE/traefik/bin/traefik}"
CONFIG_PATH="${TRAEFIK_CONNECTOR_CONFIG:-$CONNECTOR_DIR/config/traefik-forwardauth.conf}"
TRAEFIK_TEMPLATE="${TRAEFIK_CONNECTOR_TRAEFIK_CONFIG:-$CONNECTOR_DIR/config/traefik-forwardauth-dynamic.yaml}"
OBSERVER_BUILD_SCRIPT="${TRAEFIK_RESPONSE_OBSERVER_BUILD:-$CONNECTOR_DIR/build/build-response-observer.sh}"
OBSERVER_SOURCE="$CONNECTOR_DIR/response_observer"
OBSERVER_MODULE="github.com/Easton97-Jens/ModSecurity-conector/connectors/traefik/response_observer"
SERVICE_LISTEN="${TRAEFIK_CONNECTOR_LISTEN:-127.0.0.1:19090}"
TRAEFIK_LISTEN="${TRAEFIK_START_LISTEN:-127.0.0.1:19080}"
UPSTREAM_ADDRESS="${TRAEFIK_START_UPSTREAM:-127.0.0.1:19091}"
START_ROOT="${TRAEFIK_CONNECTOR_START_ROOT:-$BUILD_ROOT/traefik-connector/start-smoke}"
SERVICE_STDOUT="$START_ROOT/service.stdout.log"
SERVICE_STDERR="$START_ROOT/service.stderr.log"
TRAEFIK_STDOUT="$START_ROOT/traefik.stdout.log"
TRAEFIK_STDERR="$START_ROOT/traefik.stderr.log"
CONFIG_STDOUT="$START_ROOT/config-check.stdout.log"
CONFIG_STDERR="$START_ROOT/config-check.stderr.log"
SERVICE_PID_FILE="$START_ROOT/service.pid"
TRAEFIK_PID_FILE="$START_ROOT/traefik.pid"
TRAEFIK_CONFIG="$START_ROOT/traefik-dynamic.yaml"
COMPANION_DIR="$START_ROOT/mrc"
COMPANION_SOCKET="${TRAEFIK_CONNECTOR_COMPANION_SOCKET:-$COMPANION_DIR/traefik-forwardauth-companion.sock}"
service_pid=""
traefik_pid=""

require_private_directory() {
    directory=$1
    label=$2
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then
        echo "BLOCKED: $label must be an existing, non-symlink directory: $directory" >&2
        exit 77
    fi
    if [ "$(stat -c '%u' "$directory" 2>/dev/null || true)" != "$(id -u)" ]; then
        echo "BLOCKED: $label must be owned by the current user: $directory" >&2
        exit 77
    fi
    if find "$directory" -maxdepth 0 -perm /022 -print -quit | grep -q .; then
        echo "BLOCKED: $label must not be group or world writable: $directory" >&2
        exit 77
    fi
}

case "$START_ROOT" in
    /*) ;;
    *) echo "BLOCKED: TRAEFIK_CONNECTOR_START_ROOT must be absolute: $START_ROOT" >&2; exit 77 ;;
esac
case "$START_ROOT" in
    /|/tmp|/var/tmp)
        echo "BLOCKED: TRAEFIK_CONNECTOR_START_ROOT is too broad: $START_ROOT" >&2
        exit 77
        ;;
    *) ;;
esac

case "$BUILD_ROOT" in
    /*) ;;
    *) echo "BLOCKED: BUILD_ROOT must be absolute: $BUILD_ROOT" >&2; exit 77 ;;
esac
case "/$BUILD_ROOT/" in
    *"/../"*|*"/./"*)
        echo "BLOCKED: BUILD_ROOT must be canonical and contain no dot components: $BUILD_ROOT" >&2
        exit 77
        ;;
    *) ;;
esac
BUILD_ROOT_CANONICAL=$(readlink -f -- "$BUILD_ROOT" 2>/dev/null || true)
if [ -z "$BUILD_ROOT_CANONICAL" ] || [ "$BUILD_ROOT_CANONICAL" != "$BUILD_ROOT" ]; then
    echo "BLOCKED: BUILD_ROOT must resolve canonically without symlinks: $BUILD_ROOT" >&2
    exit 77
fi
require_private_directory "$BUILD_ROOT_CANONICAL" "BUILD_ROOT"

ALLOWED_START_ROOT="$BUILD_ROOT_CANONICAL/traefik-connector"
case "$START_ROOT" in
    *"/../"*|*"/.."|*"/./"*|*"/.")
        echo "BLOCKED: TRAEFIK_CONNECTOR_START_ROOT must contain no dot components: $START_ROOT" >&2
        exit 77
        ;;
    *) ;;
esac
START_ROOT_CANONICAL=$(readlink -f -- "$START_ROOT" 2>/dev/null || true)
if [ -z "$START_ROOT_CANONICAL" ] || [ "$START_ROOT_CANONICAL" != "$START_ROOT" ]; then
    echo "BLOCKED: TRAEFIK_CONNECTOR_START_ROOT must resolve canonically without symlinks: $START_ROOT" >&2
    exit 77
fi
case "$START_ROOT_CANONICAL" in
    "$ALLOWED_START_ROOT"/*) ;;
    *)
        echo "BLOCKED: TRAEFIK_CONNECTOR_START_ROOT must remain below the private build root: $START_ROOT" >&2
        exit 77
        ;;
esac
case "$START_ROOT_CANONICAL" in
    "$ALLOWED_START_ROOT")
        echo "BLOCKED: TRAEFIK_CONNECTOR_START_ROOT must not be the connector build root: $START_ROOT" >&2
        exit 77
        ;;
    *) ;;
esac
START_ROOT_ANCESTOR="$START_ROOT_CANONICAL"
while [ ! -e "$START_ROOT_ANCESTOR" ]; do
    START_ROOT_ANCESTOR=$(dirname "$START_ROOT_ANCESTOR")
done
START_ROOT_CHECK="$START_ROOT_ANCESTOR"
while :; do
    require_private_directory "$START_ROOT_CHECK" "TRAEFIK_CONNECTOR_START_ROOT ancestor"
    [ "$START_ROOT_CHECK" = "$BUILD_ROOT_CANONICAL" ] && break
    START_ROOT_CHECK=$(dirname "$START_ROOT_CHECK")
done

case "$START_ROOT" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "BLOCKED: start-smoke output must be outside the checkout: $START_ROOT" >&2
        exit 77
        ;;
    *) ;;
esac
if [ -L "$START_ROOT" ]; then
    echo "BLOCKED: TRAEFIK_CONNECTOR_START_ROOT must not be a symlink: $START_ROOT" >&2
    exit 77
fi

require_executable() {
    executable=$1
    label=$2
    case "$executable" in
        /*) ;;
        *) echo "BLOCKED: $label binary must be an absolute path: $executable" >&2; exit 77 ;;
    esac
    case "$executable" in
        /usr/*|/bin/*|/sbin/*|/opt/*)
            echo "BLOCKED: $label binary must not use a global system path: $executable" >&2
            exit 77
            ;;
        *) ;;
    esac
    if [ ! -x "$executable" ]; then
        echo "BLOCKED: $label binary is not executable: $executable" >&2
        exit 77
    fi
}

require_loopback_address() {
    address=$1
    label=$2
    case "$address" in
        127.0.0.1:*) port=${address#127.0.0.1:} ;;
        *) echo "BLOCKED: $label must use 127.0.0.1:PORT: $address" >&2; exit 77 ;;
    esac
    case "$port" in
        ''|*[!0-9]*) echo "BLOCKED: $label has an invalid port: $address" >&2; exit 77 ;;
        *) ;;
    esac
}

require_executable "$CONNECTOR_BIN" "Traefik forwardAuth connector"
require_executable "$TRAEFIK_BIN" "Traefik"
case "$OBSERVER_BUILD_SCRIPT" in
    /*) ;;
    *) echo "BLOCKED: response observer build script must be an absolute path: $OBSERVER_BUILD_SCRIPT" >&2; exit 77 ;;
esac
if [ ! -x "$OBSERVER_BUILD_SCRIPT" ]; then
    echo "BLOCKED: response observer build script is not executable: $OBSERVER_BUILD_SCRIPT" >&2
    exit 77
fi
if [ ! -d "$OBSERVER_SOURCE" ] || [ -L "$OBSERVER_SOURCE" ] || find "$OBSERVER_SOURCE" -type l -print -quit | grep -q .; then
    echo "BLOCKED: response observer source contains an unsafe symlink or is missing: $OBSERVER_SOURCE" >&2
    exit 77
fi
require_loopback_address "$SERVICE_LISTEN" "TRAEFIK_CONNECTOR_LISTEN"
require_loopback_address "$TRAEFIK_LISTEN" "TRAEFIK_START_LISTEN"
require_loopback_address "$UPSTREAM_ADDRESS" "TRAEFIK_START_UPSTREAM"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "BLOCKED: Traefik forwardAuth connector config is missing: $CONFIG_PATH" >&2
    exit 77
fi
if [ ! -f "$TRAEFIK_TEMPLATE" ]; then
    echo "BLOCKED: Traefik File Provider config template is missing: $TRAEFIK_TEMPLATE" >&2
    exit 77
fi
case "$COMPANION_SOCKET" in
    /*) ;;
    *) echo "BLOCKED: companion socket must be an absolute path: $COMPANION_SOCKET" >&2; exit 77 ;;
esac
case "$COMPANION_SOCKET" in
    *" "*|*"	"*|*"\n"*) echo "BLOCKED: companion socket contains whitespace/control data" >&2; exit 77 ;;
esac
case "$COMPANION_SOCKET" in
    "$START_ROOT"/*) ;;
    *) echo "BLOCKED: companion socket must remain below the private start root: $COMPANION_SOCKET" >&2; exit 77 ;;
esac

cleanup() {
    if [ -n "$traefik_pid" ] && kill -0 "$traefik_pid" 2>/dev/null; then
        kill "$traefik_pid" 2>/dev/null || true
        wait "$traefik_pid" 2>/dev/null || true
    fi
    if [ -n "$service_pid" ] && kill -0 "$service_pid" 2>/dev/null; then
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
    rm -f "$SERVICE_PID_FILE" "$TRAEFIK_PID_FILE"
}
trap cleanup EXIT HUP INT TERM

TRAEFIK_DIAGNOSTIC_SED_RANGE='1,160p'

rm -rf "$START_ROOT"
mkdir -p "$COMPANION_DIR"
chmod 700 "$START_ROOT" "$COMPANION_DIR"
if [ -z "${TRAEFIK_CONNECTOR_CONFIG:-}" ]; then
    # The checked-in default is a template. A fresh runner must not depend
    # on its example absolute log directory or write outside this run.
    START_CONFIG="$START_ROOT/traefik-forwardauth.conf"
    while IFS= read -r config_line || [ -n "$config_line" ]; do
        case "$config_line" in
            rules_file=*) printf 'rules_file=%s\n' "$TEST_ROOT/connector_suite/common/rules/modsecurity_targeted_smoke.conf" ;;
            event_path=*) printf 'event_path=%s\n' "$START_ROOT/events.jsonl" ;;
            *) printf '%s\n' "$config_line" ;;
        esac
    done < "$CONFIG_PATH" > "$START_CONFIG"
    CONFIG_PATH="$START_CONFIG"
fi
mkdir -p "$START_ROOT/plugins-local/src/$OBSERVER_MODULE"
cp -R "$OBSERVER_SOURCE/." "$START_ROOT/plugins-local/src/$OBSERVER_MODULE/"
chmod -R u=rwX,go= "$START_ROOT/plugins-local"
if [ -e "$COMPANION_SOCKET" ] || [ -L "$COMPANION_SOCKET" ]; then
    echo "BLOCKED: companion socket path already exists: $COMPANION_SOCKET" >&2
    exit 77
fi
if ! "$OBSERVER_BUILD_SCRIPT" build >"$START_ROOT/response-observer-build.log" 2>&1; then
    rc=$?
    echo "BLOCKED: Traefik response observer build failed (rc=$rc)" >&2
    sed -n "$TRAEFIK_DIAGNOSTIC_SED_RANGE" "$START_ROOT/response-observer-build.log" >&2
    exit 77
fi
sed \
    -e "s|__AUTH_ADDRESS__|$SERVICE_LISTEN|g" \
    -e "s|__UPSTREAM_ADDRESS__|$UPSTREAM_ADDRESS|g" \
    -e "s|__COMPANION_SOCKET__|$COMPANION_SOCKET|g" \
    "$TRAEFIK_TEMPLATE" > "$TRAEFIK_CONFIG"

# Inspect the original request line while keeping client forwarding fields
# untrusted. Traefik generates the authoritative URI for the auth exchange.
if ! grep -Fqx '        preserveRequestMethod: true' "$TRAEFIK_CONFIG" ||
    ! grep -Fqx '        trustForwardHeader: false' "$TRAEFIK_CONFIG"; then
    echo "BLOCKED: forwardAuth requires preserveRequestMethod=true and trustForwardHeader=false" >&2
    exit 77
fi

# A forwardAuth template without these settings silently drops the request
# body before the authorization service. Refuse to start such a deployment;
# P2 is buffered by the host; this remains a 4096-byte host limitation.
if ! grep -Fqx '        forwardBody: true' "$TRAEFIK_CONFIG" ||
    ! grep -Fqx '        maxBodySize: 4096' "$TRAEFIK_CONFIG"; then
    echo "BLOCKED: forwardAuth P2 requires forwardBody=true and maxBodySize=4096" >&2
    exit 77
fi


(
    cd "$REPO_ROOT"
    exec "$CONNECTOR_BIN" --check-config --config "$CONFIG_PATH"
) >"$CONFIG_STDOUT" 2>"$CONFIG_STDERR" || {
    rc=$?
    echo "FAIL: Traefik connector config check failed (rc=$rc)" >&2
    sed -n "$TRAEFIK_DIAGNOSTIC_SED_RANGE" "$CONFIG_STDERR" >&2
    exit "$rc"
}

(
    cd "$REPO_ROOT"
    MSCONNECTOR_TRAEFIK_FORWARDAUTH_COMPANION_SOCKET="$COMPANION_SOCKET" \
    exec "$CONNECTOR_BIN" \
        --serve \
        --config "$CONFIG_PATH" \
        --listen "$SERVICE_LISTEN"
) >"$SERVICE_STDOUT" 2>"$SERVICE_STDERR" &
service_pid=$!
printf '%s\n' "$service_pid" > "$SERVICE_PID_FILE"

(
    cd "$START_ROOT"
    exec "$TRAEFIK_BIN" \
        "--entryPoints.web.address=$TRAEFIK_LISTEN" \
        "--experimental.localPlugins.modsecurityResponseObserver.moduleName=$OBSERVER_MODULE" \
        --experimental.localPlugins.modsecurityResponseObserver.settings.useUnsafe=true \
        --experimental.abortOnPluginFailure=true \
        "--providers.file.filename=$TRAEFIK_CONFIG" \
        --providers.file.watch=false \
        --api=false \
        --log.level=ERROR \
        --global.sendAnonymousUsage=false \
        >"$TRAEFIK_STDOUT" 2>"$TRAEFIK_STDERR"
) &
traefik_pid=$!
printf '%s\n' "$traefik_pid" > "$TRAEFIK_PID_FILE"

attempt=0
while [ "$attempt" -lt 20 ]; do
    if ! kill -0 "$service_pid" 2>/dev/null; then
        wait "$service_pid" || rc=$?
        rc=${rc:-1}
        echo "FAIL: Traefik forwardAuth service exited during start smoke (rc=$rc)" >&2
        sed -n "$TRAEFIK_DIAGNOSTIC_SED_RANGE" "$SERVICE_STDERR" >&2
        exit "$rc"
    fi
    if ! kill -0 "$traefik_pid" 2>/dev/null; then
        wait "$traefik_pid" || rc=$?
        rc=${rc:-1}
        echo "FAIL: Traefik exited during start smoke (rc=$rc)" >&2
        sed -n "$TRAEFIK_DIAGNOSTIC_SED_RANGE" "$TRAEFIK_STDERR" >&2
        exit "$rc"
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

if [ -s "$TRAEFIK_STDERR" ]; then
    echo "FAIL: Traefik reported a configuration/start error" >&2
    sed -n "$TRAEFIK_DIAGNOSTIC_SED_RANGE" "$TRAEFIK_STDERR" >&2
    exit 1
fi

printf 'traefik_connector_start_smoke=pass\n'
printf 'service_listen=%s\n' "$SERVICE_LISTEN"
printf 'traefik_listen=%s\n' "$TRAEFIK_LISTEN"
printf 'service_pid=%s\n' "$service_pid"
printf 'traefik_pid=%s\n' "$traefik_pid"
printf 'traefik_config=%s\n' "$TRAEFIK_CONFIG"
printf 'response_observer_build_log=%s\n' "$START_ROOT/response-observer-build.log"
printf 'companion_socket=%s\n' "$COMPANION_SOCKET"
printf 'service_stdout_log=%s\n' "$SERVICE_STDOUT"
printf 'service_stderr_log=%s\n' "$SERVICE_STDERR"
printf 'traefik_stdout_log=%s\n' "$TRAEFIK_STDOUT"
printf 'traefik_stderr_log=%s\n' "$TRAEFIK_STDERR"
