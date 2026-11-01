#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
EXT_PROC_ROOT="$CONNECTOR_DIR/ext_proc"
CONFIG_MATERIALIZER="$CONNECTOR_DIR/config/prepare_envoy_ext_proc_config.sh"
RUNTIME_CONFIG_MATERIALIZER="$CONNECTOR_DIR/config/prepare_envoy_ext_proc_runtime_config.sh"
COMMON_BUILD="$CONNECTOR_DIR/build/build_ext_proc.sh"

if [ "${ON_DEMAND_TESTS:-0}" != 1 ]; then
    exec "${PYTHON:-python3}" "$CONNECTOR_DIR/../../ci/tools/run-active-tests.py" --group envoy
fi

command -v go >/dev/null 2>&1 || {
    echo "envoy_ext_proc_test: missing Go toolchain" >&2
    exit 77
}
[ -f "$EXT_PROC_ROOT/go.mod" ] || {
    echo "envoy_ext_proc_test: missing pinned Go module: $EXT_PROC_ROOT/go.mod" >&2
    exit 77
}
[ -x "$CONFIG_MATERIALIZER" ] || {
    echo "envoy_ext_proc_test: missing ext_proc config materializer: $CONFIG_MATERIALIZER" >&2
    exit 77
}
[ -f "$RUNTIME_CONFIG_MATERIALIZER" ] || {
    echo "envoy_ext_proc_test: missing Common runtime config materializer: $RUNTIME_CONFIG_MATERIALIZER" >&2
    exit 77
}
[ -x "$COMMON_BUILD" ] || {
    echo "envoy_ext_proc_test: missing Common bridge build script: $COMMON_BUILD" >&2
    exit 77
}

(
    cd "$EXT_PROC_ROOT"
    GOWORK=off go test -mod=readonly ./...
)

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/msconnector-envoy-ext-proc-test.XXXXXX")
cleanup() {
    rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM
generated_config="$temporary_root/envoy-ext-proc.streaming.yaml"
tls_certificate="$temporary_root/envoy-loopback.crt"
tls_private_key="$temporary_root/envoy-loopback.key"
OUTPUT_CONFIG="$generated_config" LISTEN_PORT=18080 UPSTREAM_PORT=18081 \
    EXT_PROC_PORT=18083 ADMIN_PORT=19001 \
    TLS_CERTIFICATE="$tls_certificate" TLS_PRIVATE_KEY="$tls_private_key" \
    sh "$CONFIG_MATERIALIZER" >/dev/null
[ -f "$generated_config" ] || {
    echo "envoy_ext_proc_test: config materializer did not create output" >&2
    exit 1
}
if ! grep -Fq 'request_attributes:' "$generated_config"; then
    echo "envoy_ext_proc_test: generated config is missing request_attributes" >&2
    exit 1
fi
for required_attribute in request.protocol source.address source.port destination.address destination.port; do
    if ! grep -Fq "$required_attribute" "$generated_config"; then
        echo "envoy_ext_proc_test: generated config is missing required attribute: $required_attribute" >&2
        exit 1
    fi
done
if ! grep -Fq 'request_trailer_mode: SEND' "$generated_config" || \
    ! grep -Fq 'response_trailer_mode: SEND' "$generated_config"; then
    echo "envoy_ext_proc_test: generated config does not send trailer EOS" >&2
    exit 1
fi
if ! grep -Fq 'name: envoy.transport_sockets.tls' "$generated_config" || \
    ! grep -Fq "filename: \"$tls_certificate\"" "$generated_config" || \
    ! grep -Fq "filename: \"$tls_private_key\"" "$generated_config"; then
    echo "envoy_ext_proc_test: generated config does not enable the private loopback TLS listener" >&2
    exit 1
fi

runtime_config="$temporary_root/envoy-ext-proc-runtime.conf"
common_event_log="$temporary_root/common-events.jsonl"
canonical_rules="$CONNECTOR_DIR/../../modules/ModSecurity-test-Framework/tests/rules/no-crs-baseline.conf"
canonical_rules=$(CDPATH= cd "$(dirname "$canonical_rules")" && pwd)/$(basename "$canonical_rules")
MSCONNECTOR_RULES_FILE="$canonical_rules" RULES_FILE="$temporary_root/not-the-canonical-rules.conf" \
    EVENT_PATH="$common_event_log" OUTPUT_CONFIG="$runtime_config" sh "$RUNTIME_CONFIG_MATERIALIZER" >/dev/null
for required_setting in \
    'request_body_mode=streaming' \
    'response_body_mode=streaming' \
    'phase4_mode=safe'
do
    if ! grep -Fqx "$required_setting" "$runtime_config"; then
        echo "envoy_ext_proc_test: generated Common runtime config is missing $required_setting" >&2
        exit 1
    fi
done
if ! grep -Fqx "event_path=$common_event_log" "$runtime_config"; then
    echo "envoy_ext_proc_test: Common runtime config does not select its run-local raw event path" >&2
    exit 1
fi
if ! grep -Fqx "rules_file=$canonical_rules" "$runtime_config"; then
    echo "envoy_ext_proc_test: Common runtime config did not prefer MSCONNECTOR_RULES_FILE" >&2
    exit 1
fi

modsecurity_include=${MODSECURITY_INCLUDE_DIR:-${MODSECURITY_PREFIX:+$MODSECURITY_PREFIX/include}}
modsecurity_library=${MODSECURITY_LIB_FILE:-}
if [ -z "$modsecurity_library" ] && [ -n "${MODSECURITY_LIB_DIR:-${MODSECURITY_PREFIX:+$MODSECURITY_PREFIX/lib}}" ]; then
    modsecurity_library=${MODSECURITY_LIB_DIR:-${MODSECURITY_PREFIX:+$MODSECURITY_PREFIX/lib}}/libmodsecurity.so
fi
if [ -n "$modsecurity_include" ] && [ -f "$modsecurity_include/modsecurity/modsecurity.h" ] && \
    [ -n "$modsecurity_library" ] && [ -f "$modsecurity_library" ]; then
    ENVOY_EXT_PROC_COMMON_TEST=1 BUILD_ROOT="${BUILD_ROOT:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/ModSecurity-conector-build}" \
        MODSECURITY_INCLUDE_DIR="$modsecurity_include" \
        MODSECURITY_LIB_DIR="${MODSECURITY_LIB_DIR:-}" \
        MODSECURITY_LIB_FILE="${MODSECURITY_LIB_FILE:-}" \
        MODSECURITY_PREFIX="${MODSECURITY_PREFIX:-}" \
        CC="${CC:-cc}" CFLAGS="${CFLAGS:-}" AR="${AR:-ar}" \
        sh "$COMMON_BUILD"
else
    echo "envoy_ext_proc_test: Common/libmodsecurity bridge tests not executed (set MODSECURITY_INCLUDE_DIR and MODSECURITY_LIB_DIR or MODSECURITY_LIB_FILE)" >&2
fi
