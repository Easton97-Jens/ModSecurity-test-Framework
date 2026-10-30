#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
set -eu

connector=${1:?connector is required}
evidence_stage=${2:-no_crs_baseline}
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
PYTHON=${PYTHON:-python3}
VERIFIED_RUN_ROOT=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-verified}
# Keep the invocation-level root distinct from the connector-local raw run.
# The resolver intentionally places build/, runs/, and run-logs/ beside one
# another. Framework host checks may need to see all three as safe runtime
# descendants, so passing only CONNECTOR_RUN_ROOT would incorrectly reject the
# sibling connector build root.
CANONICAL_VERIFIED_RUN_ROOT=$VERIFIED_RUN_ROOT
BUILD_ROOT=${BUILD_ROOT:-$VERIFIED_RUN_ROOT/build}
VERIFIED_EVIDENCE_ROOT=${VERIFIED_EVIDENCE_ROOT:-$VERIFIED_RUN_ROOT/evidence}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-$VERIFIED_EVIDENCE_ROOT/no-crs-evidence}
RUNTIME_RUN_ROOT=${RUNTIME_RUN_ROOT:-$VERIFIED_RUN_ROOT/runs}
RUNTIME_LOG_ROOT=${RUNTIME_LOG_ROOT:-$VERIFIED_RUN_ROOT/run-logs}
CACHE_ROOT=${CACHE_ROOT:-$VERIFIED_RUN_ROOT/cache-v2}
NO_CRS_RUN_ID=${NO_CRS_RUN_ID:-$(date -u +%Y-%m-%dT%H-%M-%SZ)-$(git -C "$CONNECTOR_ROOT" rev-parse --short=8 HEAD 2>/dev/null || printf unknown)}
NO_CRS_RULES_FILE=${NO_CRS_RULES_FILE:-$FRAMEWORK_ROOT/tests/rules/no-crs-baseline.conf}
NO_CRS_ARTIFACT_PROFILE=${NO_CRS_ARTIFACT_PROFILE:-generic}
FIVE_CONNECTOR_PROFILE=${FIVE_CONNECTOR_PROFILE:-}
FIVE_CONNECTOR_PARENT_COMMIT=${FIVE_CONNECTOR_PARENT_COMMIT:-}
FIVE_CONNECTOR_FRAMEWORK_COMMIT=${FIVE_CONNECTOR_FRAMEWORK_COMMIT:-}
NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR=${NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR:-}
NO_CRS_PROTOCOL_CLIENT=${NO_CRS_PROTOCOL_CLIENT:-0}
FULL_LIFECYCLE_HOST_PROFILE=${FULL_LIFECYCLE_HOST_PROFILE:-}
FULL_LIFECYCLE_EXECUTED_TARGET=${FULL_LIFECYCLE_EXECUTED_TARGET:-}
EXPECTED_RULE_ID=1100001

# Native operation authority is a separate explicit source/build boundary.
# This helper runs only after canonical init has preserved the required rows.
prepare_nginx_native_authority() {
    NGINX_NATIVE_AUTHORITY_ENABLED=0
    NGINX_NATIVE_AUTHORITY=
    NGINX_NATIVE_AUTHORITY_PREFIX=
    if [ "$connector:$NO_CRS_ARTIFACT_PROFILE" != nginx:full_lifecycle ]; then
        return 0
    fi
    native_selected=$("$PYTHON" - "$FRAMEWORK_ROOT" "$NO_CRS_SELECTED_CASE_IDS" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

framework = Path(sys.argv[1])
reader_path = framework / "tests/runners/nginx_native_operation_bundle.py"
spec = importlib.util.spec_from_file_location("native_authority_selection", reader_path)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
catalog = json.loads((framework / "tests/cases/no-crs-baseline/catalog.json").read_text(encoding="utf-8"))
selected = set(sys.argv[2].split())
cases = catalog["cases"]
if len({case["case_id"] for case in cases}) != len(cases):
    raise SystemExit("duplicate native catalog case identity")
native = selected & reader.CASE_IDS
found = set()
for case in cases:
    case_id = case["case_id"]
    if case_id not in selected:
        continue
    descriptor = case.get("native_invocations", {}).get("nginx")
    if case_id in native and not isinstance(descriptor, dict):
        raise SystemExit("selected required native case has no descriptor")
    if descriptor is not None:
        if case_id not in reader.CASE_IDS:
            raise SystemExit("native descriptor outside closed operation registry")
        found.add(case_id)
if native != found:
    raise SystemExit("selected required native case absent from catalog")
print("1" if native else "0")
PY
    ) || {
        echo "FAIL: unable to bind selected native authority descriptors" >&2
        return 1
    }
    if [ "$native_selected" = 0 ]; then
        return 0
    fi
    NGINX_NATIVE_AUTHORITY_ENABLED=1
    NGINX_NATIVE_AUTHORITY_PREFIX=${NGINX_PREFIX:-}
    if [ -z "$NGINX_NATIVE_AUTHORITY_PREFIX" ]; then
        echo "BLOCKED: selected native operations require explicit prepared NGINX_PREFIX" >&2
        return 77
    fi
    for native_library in \
        "${NGX_NATIVE_INPUT_FAULT_LIBRARY:-}" \
        "${NGX_NATIVE_BEGIN_FAULT_LIBRARY:-}" \
        "${NGX_NATIVE_FINISH_FAULT_LIBRARY:-}" \
        "${NGX_NATIVE_WRITE_FAULT_LIBRARY:-}" \
        "${NGX_NATIVE_ENGINE_BUDGET_FAULT_LIBRARY:-}"; do
        if [ -z "$native_library" ] || [ ! -f "$native_library" ]; then
            echo "BLOCKED: selected native operations require all five explicit compiled fault libraries" >&2
            return 77
        fi
    done
    native_authority_producer=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/nginx_native_authority.py
    if [ ! -f "$native_authority_producer" ]; then
        echo "BLOCKED: explicit native authority producer is missing" >&2
        return 77
    fi
    native_authority_parent=$("$PYTHON" - "$CONNECTOR_ROOT" "$STAGE_BUILD_ROOT" "$NO_CRS_RUN_ID" <<'PY'
import os
import re
import sys
from pathlib import Path

from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory

stage = Path(sys.argv[2])
run_id = sys.argv[3]
if not stage.is_absolute() or ".." in stage.parts or not stage.is_relative_to(Path("/var/tmp/codex/ModSecurity-conector")):
    raise SystemExit("native authority requires explicit external stage build root")
if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id) is None:
    raise SystemExit("native authority requires bounded run identity")
host = ensure_safe_runtime_directory(stage / "host-runtime")
descriptor = os.open(host, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    leaf = "native-authority-" + run_id
    os.mkdir(leaf, 0o700, dir_fd=descriptor)
finally:
    os.close(descriptor)
print(host / leaf)
PY
    ) || {
        echo "FAIL: unable to reserve fresh private native authority parent" >&2
        return 1
    }
    "$PYTHON" "$native_authority_producer" \
        --parent-root "$CONNECTOR_ROOT" \
        --framework-root "$FRAMEWORK_ROOT" \
        --mrts-root "${MRTS_ROOT:-$FRAMEWORK_ROOT/tools/MRTS}" \
        --run-id "$NO_CRS_RUN_ID" \
        --artifact-root "$STAGE_BUILD_ROOT" \
        --binary-path "$NGINX_NATIVE_AUTHORITY_PREFIX/sbin/nginx" \
        --module-path "$NGINX_NATIVE_AUTHORITY_PREFIX/modules/ngx_http_modsecurity_module.so" \
        --input-fault-library "$NGX_NATIVE_INPUT_FAULT_LIBRARY" \
        --begin-fault-library "$NGX_NATIVE_BEGIN_FAULT_LIBRARY" \
        --finish-fault-library "$NGX_NATIVE_FINISH_FAULT_LIBRARY" \
        --write-fault-library "$NGX_NATIVE_WRITE_FAULT_LIBRARY" \
        --budget-fault-library "$NGX_NATIVE_ENGINE_BUDGET_FAULT_LIBRARY" \
        --output-parent "$native_authority_parent" || {
            echo "FAIL: explicit native operation authority could not be sealed" >&2
            return 1
        }
    NGINX_NATIVE_AUTHORITY=$native_authority_parent/native-operation-authority.json
}

case "$connector" in
    apache|nginx|haproxy|envoy|traefik|lighttpd) ;;
    *) echo "usage: $0 apache|nginx|haproxy|envoy|traefik|lighttpd" >&2; exit 2 ;;
esac
case "$evidence_stage" in
    minimal_runtime_smoke|no_crs_baseline) ;;
    *) echo "usage: $0 connector [minimal_runtime_smoke|no_crs_baseline]" >&2; exit 2 ;;
esac
case "$NO_CRS_ARTIFACT_PROFILE" in
    generic|full_lifecycle) ;;
    *) echo "FAIL: unsupported NO_CRS_ARTIFACT_PROFILE: $NO_CRS_ARTIFACT_PROFILE" >&2; exit 2 ;;
esac
case "$NO_CRS_PROTOCOL_CLIENT" in
    0|false|no|"") NO_CRS_PROTOCOL_CLIENT=0 ;;
    1|true|yes) NO_CRS_PROTOCOL_CLIENT=1 ;;
    *) echo "FAIL: NO_CRS_PROTOCOL_CLIENT must be 0 or 1" >&2; exit 1 ;;
esac
if { [ -n "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" ] || \
     [ "$NO_CRS_PROTOCOL_CLIENT" = 1 ]; } && \
   [ "$NO_CRS_ARTIFACT_PROFILE" != full_lifecycle ]; then
    echo "FAIL: NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR requires NO_CRS_ARTIFACT_PROFILE=full_lifecycle" >&2
    exit 1
fi
case "$NO_CRS_RUN_ID" in
    [A-Za-z0-9]* ) ;;
    *) echo "FAIL: run id must start with an ASCII letter or digit: $NO_CRS_RUN_ID" >&2; exit 1 ;;
esac
case "$NO_CRS_RUN_ID" in
    *[!A-Za-z0-9._-]*) echo "FAIL: run id contains unsafe characters: $NO_CRS_RUN_ID" >&2; exit 1 ;;
    *) ;;
esac
if [ "${#NO_CRS_RUN_ID}" -gt 128 ]; then
    echo "FAIL: run id exceeds 128 characters" >&2
    exit 1
fi
CAPABILITIES_FILE=$CONNECTOR_ROOT/connectors/$connector/capabilities.json
RUNTIME_PATH_RESOLVER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/common/resolve-runtime-paths.py
PROFILE_RESOLVER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/resolve-full-lifecycle-profile.py
FIVE_CONNECTOR_PROFILE_RESOLVER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/five-connector-no-crs-profile.py
LOG_SANITIZER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/sanitize-full-lifecycle-log.py
ENGINE_ARTIFACT_WRITER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-engine-lifecycle-artifacts.py
FIRST_NONEMPTY_OUTPUT_LINE_SED_SCRIPT='/./{p;q;}'
TRANSPORT_ARTIFACT_WRITER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-transport-lifecycle-artifacts.py
HOSTRUNTIME_RECORD_WRITER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/write-hostruntime-record.py
LIGHTTPD_HOST_BINARY_RESOLVER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/resolve-lighttpd-host-binary.py
TRAEFIK_HOST_BINARY_RESOLVER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/resolve-traefik-host-binary.py
TRAEFIK_ARTIFACT_STAGER=$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/stage-traefik-runtime-artifacts.py
SYNCHRONIZED_UPSTREAM=$FRAMEWORK_ROOT/tests/runners/synchronized_upstream.py

# Reject a future/unknown closed profile before consulting Framework tooling,
# builds, or runtime roots.  The selected connector must also be one of the
# profile's fixed rows, so this mode cannot reach a generic connector route.
[ -f "$CAPABILITIES_FILE" ] || {
    echo "FAIL: connector capability manifest is missing: $CAPABILITIES_FILE" >&2
    exit 1
}
[ -z "$FIVE_CONNECTOR_PROFILE" ] || [ -f "$FIVE_CONNECTOR_PROFILE_RESOLVER" ] || {
    echo "FAIL: five-connector profile resolver is missing: $FIVE_CONNECTOR_PROFILE_RESOLVER" >&2
    exit 1
}
five_connector_profile_enabled=0
if [ -n "$FIVE_CONNECTOR_PROFILE" ]; then
    "$PYTHON" "$FIVE_CONNECTOR_PROFILE_RESOLVER" \
        --profile "$FIVE_CONNECTOR_PROFILE" \
        --verify-connector \
        --connector "$connector"
    if [ "$NO_CRS_ARTIFACT_PROFILE" != generic ]; then
        echo "FAIL: the closed five-connector profile requires NO_CRS_ARTIFACT_PROFILE=generic" >&2
        exit 1
    fi
    five_connector_profile_enabled=1
fi

[ -f "$FRAMEWORK_ROOT/ci/checks/catalog/no_crs_baseline.py" ] || {
    echo "BLOCKED: canonical framework runner is missing: $FRAMEWORK_ROOT/ci/checks/catalog/no_crs_baseline.py" >&2
    exit 77
}
[ -f "$LOG_SANITIZER" ] || {
    echo "FAIL: canonical log sanitizer is missing: $LOG_SANITIZER" >&2
    exit 1
}
[ -f "$ENGINE_ARTIFACT_WRITER" ] || {
    echo "FAIL: engine lifecycle artifact writer is missing: $ENGINE_ARTIFACT_WRITER" >&2
    exit 1
}
[ -f "$TRANSPORT_ARTIFACT_WRITER" ] || {
    echo "FAIL: transport lifecycle artifact writer is missing: $TRANSPORT_ARTIFACT_WRITER" >&2
    exit 1
}
[ -f "$HOSTRUNTIME_RECORD_WRITER" ] || {
    echo "FAIL: hostruntime record writer is missing: $HOSTRUNTIME_RECORD_WRITER" >&2
    exit 1
}
[ -f "$LIGHTTPD_HOST_BINARY_RESOLVER" ] || {
    echo "FAIL: Lighttpd host-binary resolver is missing: $LIGHTTPD_HOST_BINARY_RESOLVER" >&2
    exit 1
}
[ -f "$TRAEFIK_HOST_BINARY_RESOLVER" ] || {
    echo "FAIL: Traefik host-binary resolver is missing: $TRAEFIK_HOST_BINARY_RESOLVER" >&2
    exit 1
}
[ -f "$TRAEFIK_ARTIFACT_STAGER" ] || {
    echo "FAIL: Traefik runtime artifact stager is missing: $TRAEFIK_ARTIFACT_STAGER" >&2
    exit 1
}
[ -f "$SYNCHRONIZED_UPSTREAM" ] || {
    echo "FAIL: synchronized upstream helper is missing: $SYNCHRONIZED_UPSTREAM" >&2
    exit 1
}
[ -f "$RUNTIME_PATH_RESOLVER" ] || {
    echo "FAIL: runtime path resolver is missing: $RUNTIME_PATH_RESOLVER" >&2
    exit 1
}
[ -f "$PROFILE_RESOLVER" ] || {
    echo "FAIL: full-lifecycle profile resolver is missing: $PROFILE_RESOLVER" >&2
    exit 1
}
[ -f "$NO_CRS_RULES_FILE" ] || {
    echo "FAIL: canonical no-CRS rules are missing: $NO_CRS_RULES_FILE" >&2
    exit 1
}

# The reusable workflow supplies both checkout identities.  Resolve and bind
# them after the normal Framework presence checks, still before any runtime or
# evidence directory exists.  The generic master runner remains unchanged
# whenever no closed profile is selected.
if [ "$five_connector_profile_enabled" -eq 1 ]; then
    if [ -z "$FIVE_CONNECTOR_PARENT_COMMIT$FIVE_CONNECTOR_FRAMEWORK_COMMIT" ]; then
        echo "FAIL: the closed five-connector profile requires parent and Framework commit identities" >&2
        exit 1
    fi
    actual_parent_commit=$(git -C "$CONNECTOR_ROOT" rev-parse HEAD) || {
        echo "FAIL: cannot resolve the current Parent commit for the closed profile" >&2
        exit 1
    }
    actual_framework_commit=$(git -C "$FRAMEWORK_ROOT" rev-parse HEAD) || {
        echo "FAIL: cannot resolve the current Framework commit for the closed profile" >&2
        exit 1
    }
    if [ "$FIVE_CONNECTOR_PARENT_COMMIT" != "$actual_parent_commit" ] || \
       [ "$FIVE_CONNECTOR_FRAMEWORK_COMMIT" != "$actual_framework_commit" ]; then
        echo "FAIL: closed five-connector profile commit identity does not match this checkout" >&2
        exit 1
    fi
fi

expected_full_lifecycle_profile() {
    requested_connector=$1
    case "$requested_connector" in
        apache) printf '%s\n' native-httpd-module ;;
        nginx) printf '%s\n' native-nginx-http-module ;;
        haproxy) printf '%s\n' native-htx-filter ;;
        envoy) printf '%s\n' ext_proc ;;
        traefik) printf '%s\n' native-middleware ;;
        lighttpd) printf '%s\n' patched-native ;;
        *) return 1 ;;
    esac
}

expected_full_lifecycle_target() {
    requested_connector=$1
    case "$requested_connector" in
        apache) printf '%s\n' full-lifecycle-apache ;;
        nginx) printf '%s\n' full-lifecycle-nginx ;;
        haproxy) printf '%s\n' full-lifecycle-haproxy-htx ;;
        envoy) printf '%s\n' full-lifecycle-envoy-ext-proc ;;
        traefik) printf '%s\n' full-lifecycle-traefik-native ;;
        lighttpd) printf '%s\n' full-lifecycle-lighttpd-patched ;;
        *) return 1 ;;
    esac
}

if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    expected_profile=$(expected_full_lifecycle_profile "$connector")
    expected_target=$(expected_full_lifecycle_target "$connector")
    if [ "$FULL_LIFECYCLE_HOST_PROFILE" != "$expected_profile" ]; then
        echo "FAIL: full-lifecycle $connector requires host profile $expected_profile; got ${FULL_LIFECYCLE_HOST_PROFILE:-unset}" >&2
        exit 1
    fi
    if [ -z "$FULL_LIFECYCLE_EXECUTED_TARGET" ]; then
        FULL_LIFECYCLE_EXECUTED_TARGET=$expected_target
    fi
    if [ "$FULL_LIFECYCLE_EXECUTED_TARGET" != "$expected_target" ]; then
        echo "FAIL: full-lifecycle $connector requires target $expected_target; got $FULL_LIFECYCLE_EXECUTED_TARGET" >&2
        exit 1
    fi
elif [ -n "$FULL_LIFECYCLE_HOST_PROFILE$FULL_LIFECYCLE_EXECUTED_TARGET" ]; then
    echo "FAIL: full-lifecycle profile variables require NO_CRS_ARTIFACT_PROFILE=full_lifecycle" >&2
    exit 1
fi

# Selection must describe the same downstream the NGINX harness will use.
# Preserve its existing HTTP/1 default; an enhanced build profile alone does
# not select H2/H3. Other connectors and generic plans retain "any".
selection_downstream_protocol=any
if [ "$connector" = nginx ] && [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    NGINX_DOWNSTREAM_PROTOCOL=${NGINX_DOWNSTREAM_PROTOCOL:-http1}
    nginx_protocol_profile=${NGINX_PROTOCOL_PROFILE:-h1}
    case "$nginx_protocol_profile" in
        h1|h1-h2|h1-h2-h3-quic) ;;
        *) echo "FAIL: unsupported NGINX_PROTOCOL_PROFILE: $nginx_protocol_profile" >&2; exit 1 ;;
    esac
    case "$NGINX_DOWNSTREAM_PROTOCOL:$nginx_protocol_profile" in
        http1:*|h2:h1-h2|h2:h1-h2-h3-quic|h3:h1-h2-h3-quic) ;;
        *)
            echo "FAIL: incompatible NGINX_DOWNSTREAM_PROTOCOL=$NGINX_DOWNSTREAM_PROTOCOL and NGINX_PROTOCOL_PROFILE=$nginx_protocol_profile" >&2
            exit 1
            ;;
    esac
    selection_downstream_protocol=$NGINX_DOWNSTREAM_PROTOCOL
    export NGINX_DOWNSTREAM_PROTOCOL
fi

# One resolver owns every connector-local path.  It deliberately does not use
# legacy connector-specific environment variables, which prevents a later
# stage from inheriting another connector's build or run root.
runtime_paths=$("$PYTHON" "$RUNTIME_PATH_RESOLVER" \
    --connector "$connector" \
    --run-id "$NO_CRS_RUN_ID" \
    --invocation-root "$CANONICAL_VERIFIED_RUN_ROOT" \
    --evidence-root "$EVIDENCE_ROOT" \
    --build-root "$BUILD_ROOT" \
    --run-root "$RUNTIME_RUN_ROOT" \
    --log-root "$RUNTIME_LOG_ROOT" \
    --cache-root "$CACHE_ROOT" \
    --format shell) || {
    echo "FAIL: unable to resolve isolated runtime paths for $connector/$NO_CRS_RUN_ID" >&2
    exit 1
}
# The resolver emits shell-quoted export assignments only.  It validates every
# input before output and performs no filesystem mutation.
# shellcheck disable=SC2086
eval "$runtime_paths"
EVIDENCE_ROOT=$(dirname "$(dirname "$EVIDENCE_RUN_ROOT")")
BUILD_ROOT=$CONNECTOR_BUILD_ROOT
CONNECTOR_COMPONENT_CACHE=$SHARED_COMPONENT_CACHE
VERIFIED_COMPONENT_CACHE=$SHARED_COMPONENT_CACHE
CACHE_ROOT=$(dirname "$SHARED_COMPONENT_CACHE")
RUN_DIR=$EVIDENCE_RUN_ROOT
RAW_DIR=$CONNECTOR_RUN_ROOT
LOG_DIR=$CONNECTOR_LOG_ROOT
RESULTS_DIR=$CONNECTOR_RUN_ROOT/results
HOST_RUNTIME_ROOT=$CONNECTOR_RUN_ROOT/host-runtime
HOST_LOG_ROOT=$CONNECTOR_LOG_ROOT/host
HOST_TMP_ROOT=$CONNECTOR_RUN_ROOT/tmp
STAGE_BUILD_ROOT=$CONNECTOR_BUILD_ROOT
STAGE_TMP_ROOT=$HOST_TMP_ROOT
STAGE_LOG_ROOT=$HOST_LOG_ROOT
STAGE_RESULTS_DIR=$RESULTS_DIR
STAGE_RUNTIME_ROOT=$HOST_RUNTIME_ROOT
# The Framework host smoke contract requires its build, temporary, log,
# and result roots to be nested together. This is a disposable *host work*
# directory inside the already-isolated raw run, not the connector build root
# resolved above; shared component artifacts still remain under
# CONNECTOR_BUILD_ROOT and Cache-v2.
case "$connector" in
    nginx)
        STAGE_BUILD_ROOT=$CONNECTOR_RUN_ROOT/nginx-host-work
        STAGE_TMP_ROOT=$STAGE_BUILD_ROOT/tmp
        STAGE_LOG_ROOT=$STAGE_BUILD_ROOT/logs
        STAGE_RESULTS_DIR=$STAGE_BUILD_ROOT/results
        STAGE_RUNTIME_ROOT=$STAGE_BUILD_ROOT/runtime
        ;;
    haproxy)
        STAGE_BUILD_ROOT=$CONNECTOR_RUN_ROOT/haproxy-host-work
        STAGE_TMP_ROOT=$STAGE_BUILD_ROOT/tmp
        STAGE_LOG_ROOT=$STAGE_BUILD_ROOT/logs
        STAGE_RESULTS_DIR=$STAGE_BUILD_ROOT/results
        STAGE_RUNTIME_ROOT=$STAGE_BUILD_ROOT/runtime
        ;;
    *) ;;
esac
NGINX_RUN_ROOT=$CONNECTOR_RUN_ROOT/nginx-harness
STAGE_NGINX_HARNESS_PARENT=$RAW_DIR
NGINX_DOCROOT_PROJECTION=0
if [ "$connector" = nginx ]; then
    NGINX_RUN_ROOT=$STAGE_BUILD_ROOT/nginx-harness
    STAGE_NGINX_HARNESS_PARENT=$STAGE_BUILD_ROOT
    # Keep Framework case materialization private.  The NGINX harness creates
    # a separate, validated worker-visible static docroot only for this
    # canonical lifecycle route.
    NGINX_DOCROOT_PROJECTION=1
fi
# Traefik's runtime writer rejects result paths outside its trusted build
# root.  Keep this connector-local output below the resolver-selected mutable
# build tree rather than weakening that containment guard.
TRAEFIK_RUNTIME_ROOT=$STAGE_BUILD_ROOT/traefik-runtime
LIGHTTPD_RUNTIME_ROOT=$CONNECTOR_RUN_ROOT/lighttpd-runtime
PLAN=$CONNECTOR_RUN_ROOT/plan.json
SOURCE_RESULT=$CONNECTOR_RUN_ROOT/source-result.json
NORMALIZED_EVENTS=$CONNECTOR_RUN_ROOT/events.normalized.jsonl
# The collector writes this diagnostic record under the paired lifecycle log
# root while it removes raw source events from the separate raw run.
SOURCE_EVENT_SCRUB_LOG=$CONNECTOR_LOG_ROOT/source-event-scrub.log
CANONICAL_STDOUT_LOG=$CONNECTOR_LOG_ROOT/stdout.canonical.log
CANONICAL_STDERR_LOG=$CONNECTOR_LOG_ROOT/stderr.canonical.log
CANONICAL_HOST_LOG=$CONNECTOR_LOG_ROOT/host.canonical.log
FIRST_BYTE_EVIDENCE=$CONNECTOR_RUN_ROOT/first-byte-evidence.json
FIRST_BYTE_EVIDENCE_SOURCE=${FIRST_BYTE_EVIDENCE_SOURCE:-}
STAGE_FIRST_BYTE_EVIDENCE_OUTPUT=$FIRST_BYTE_EVIDENCE
if [ "$connector" = lighttpd ] && [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    # The Lighttpd harness owns only its dedicated smoke root and correctly
    # rejects a parent-run output.  Keep its host-produced source inside that
    # root; the existing finalizer validates and copies it into the canonical
    # connector-run destination below.
    LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE=$LIGHTTPD_RUNTIME_ROOT/first-byte-evidence.json
    STAGE_FIRST_BYTE_EVIDENCE_OUTPUT=$LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE
    FIRST_BYTE_EVIDENCE_SOURCE=$LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE
fi
ENGINE_ARTIFACT_DIR=$CONNECTOR_RUN_ROOT/engine-artifacts
ENGINE_VERSION_ARTIFACT=$ENGINE_ARTIFACT_DIR/engine-version.txt
ENGINE_LIBRARY_SHA256_ARTIFACT=$ENGINE_ARTIFACT_DIR/engine-library-sha256.txt
RULESET_SHA256_ARTIFACT=$ENGINE_ARTIFACT_DIR/ruleset-sha256.txt
TRANSACTION_COUNTS_ARTIFACT=$ENGINE_ARTIFACT_DIR/transaction-counts.json
LIFECYCLE_COUNTERS_ARTIFACT=$ENGINE_ARTIFACT_DIR/lifecycle-counters.json
TRANSPORT_ARTIFACT_DIR=$CONNECTOR_RUN_ROOT/transport-artifacts
CLIENT_TRANSPORT_LOG=$TRANSPORT_ARTIFACT_DIR/client.log
UPSTREAM_TRANSPORT_LOG=$TRANSPORT_ARTIFACT_DIR/upstream.log
TRANSPORT_LOG=$TRANSPORT_ARTIFACT_DIR/transport.log
CLEANUP_TRANSPORT_LOG=$TRANSPORT_ARTIFACT_DIR/cleanup.log
TRANSPORT_OBSERVATIONS_ARTIFACT=$TRANSPORT_ARTIFACT_DIR/transport-observations.json
CONNECTION_LIFECYCLE_ARTIFACT=$TRANSPORT_ARTIFACT_DIR/connection-lifecycle.json
BARRIER_EVENTS_ARTIFACT=$TRANSPORT_ARTIFACT_DIR/barrier-events.jsonl
EFFECTIVE_CONFIG_ARTIFACT_DIR=$CONNECTOR_RUN_ROOT/effective-config
EFFECTIVE_CONFIG_MANIFEST=$EFFECTIVE_CONFIG_ARTIFACT_DIR/manifest.json
EFFECTIVE_CAPABILITIES_FILE=$CAPABILITIES_FILE
protocol_client_artifact_optional=0
if [ "$NO_CRS_PROTOCOL_CLIENT" = 1 ] && [ -z "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" ]; then
    # The raw run does not exist yet, so only the canonical runner can choose
    # this safe location. A host that cannot reach its selected protocol path
    # may leave the optional bundle absent; that remains non-promoting.
    NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR=$RAW_DIR/protocol-client
    protocol_client_artifact_optional=1
fi
FULL_LIFECYCLE_STAGE_REASON=
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    EFFECTIVE_CAPABILITIES_FILE=$CONNECTOR_BUILD_ROOT/effective-full-lifecycle-capabilities.json
    "$PYTHON" "$PROFILE_RESOLVER" \
        --input "$CAPABILITIES_FILE" \
        --output "$EFFECTIVE_CAPABILITIES_FILE" \
        --runtime-root "$CONNECTOR_BUILD_ROOT" \
        --profile "$FULL_LIFECYCLE_HOST_PROFILE" || {
        echo "FAIL: unable to materialize effective full-lifecycle capabilities" >&2
        exit 1
    }
    CAPABILITIES_FILE=$EFFECTIVE_CAPABILITIES_FILE
    case "$connector" in
        haproxy)
            FULL_LIFECYCLE_STAGE_REASON="native HTX host runs real libmodsecurity P1--P4 with a host-buffered P2 classification, end-of-stream Phase-4 evaluation, and a safe HTTP/1.1 first-byte barrier"
            ;;
        envoy)
            FULL_LIFECYCLE_STAGE_REASON="native ext_proc host streams through Common/libmodsecurity with P1/P2/P3 and safe P4 host outcomes; strict post-commit reset remains not executed"
            ;;
        traefik)
            FULL_LIFECYCLE_STAGE_REASON="native Traefik middleware reaches a persistent local Common/libmodsecurity UDS service with P1/P2/P3 and safe P4 host outcomes; strict post-commit reset remains not executed"
            ;;
        lighttpd)
            FULL_LIFECYCLE_STAGE_REASON="patched lighttpd host runs real request/response entity-body ingestion before HTTP/1 transfer framing, end-of-stream Phase-4 evaluation, and a safe HTTP/1.1 first-byte barrier"
            ;;
        *) ;;
    esac
fi
canonical_rules_file=$("$PYTHON" -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
    "$FRAMEWORK_ROOT/tests/rules/no-crs-baseline.conf") || {
    echo "FAIL: cannot resolve canonical framework rules" >&2
    exit 1
}
executed_rules_file=$("$PYTHON" -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' \
    "$NO_CRS_RULES_FILE") || {
    echo "FAIL: cannot resolve requested no-CRS rules" >&2
    exit 1
}
if [ "$executed_rules_file" != "$canonical_rules_file" ]; then
    echo "FAIL: canonical baseline may only execute $canonical_rules_file" >&2
    exit 1
fi
NO_CRS_RULES_FILE=$canonical_rules_file

case "$RUN_DIR" in
    /*) ;;
    *) echo "BLOCKED: canonical run directory must be absolute: $RUN_DIR" >&2; exit 77 ;;
esac
case "$RUN_DIR" in
    "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
        echo "BLOCKED: canonical evidence must be outside the checkout: $RUN_DIR" >&2
        exit 77
        ;;
    *) ;;
esac

reject_symlink_components() {
    candidate=$1
    while [ "$candidate" != / ]; do
        if [ -L "$candidate" ]; then
            echo "FAIL: evidence path must not contain symlinks: $candidate" >&2
            exit 1
        fi
        candidate=$(dirname "$candidate")
    done
}

case "$RAW_DIR" in
    /*) ;;
    *) echo "BLOCKED: raw evidence directory must be absolute: $RAW_DIR" >&2; exit 77 ;;
esac
case "$RAW_DIR" in
    "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*)
        echo "BLOCKED: raw evidence must be outside the checkout: $RAW_DIR" >&2
        exit 77
        ;;
    *) ;;
esac
reject_symlink_components "$RUN_DIR"
reject_symlink_components "$RAW_DIR"
if [ -n "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" ]; then
    case "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" in
        /*) ;;
        *) echo "FAIL: NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR must be absolute" >&2; exit 1 ;;
    esac
    # The harness is allowed to create the directory later, but it must be
    # scoped to this invocation's disposable raw run rather than an arbitrary
    # external tree.  Resolve and re-check it after the stage has finished.
    case "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" in
        "$RAW_DIR"/*) ;;
        *) echo "FAIL: NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR must remain inside this raw run" >&2; exit 1 ;;
    esac
    reject_symlink_components "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR"
fi
if [ -e "$RUN_DIR" ] || [ -L "$RUN_DIR" ]; then
    echo "FAIL: canonical run directory already exists; choose a fresh run id: $RUN_DIR" >&2
    exit 1
fi
if [ -e "$RAW_DIR" ] || [ -L "$RAW_DIR" ]; then
    echo "FAIL: raw evidence directory already exists; choose a fresh run id: $RAW_DIR" >&2
    exit 1
fi

if [ "$connector:$NO_CRS_ARTIFACT_PROFILE" = nginx:full_lifecycle ]; then
    # The root master creates this fresh run; its unprivileged worker must
    # traverse it to reach harness-owned state. Keep results/logs private and
    # use an exclusive leaf mkdir so an existing run is never reused/chmodded.
    mkdir -p "$(dirname "$RAW_DIR")"
    mkdir -m 0711 "$RAW_DIR"
    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
else
    mkdir -p "$RAW_DIR" "$LOG_DIR" "$RESULTS_DIR"
fi

# Reserve one exact local runtime-env destination before entering the stage.
# The stage receives this path unchanged, and this canonical runner later
# reads only that file for host inventory.  It must never reopen the mutable
# shared Cache-v2 runtime-env.sh after a concurrent connector preparation.
RUNTIME_REPORT_OUTPUT_ROOT=$CONNECTOR_BUILD_ROOT/runtime-component-reports
case "$connector" in
    apache|nginx|haproxy) canonical_runtime_component_target=$connector ;;
    envoy|traefik|lighttpd) canonical_runtime_component_target=shared ;;
    *)
        echo "FAIL: unsupported canonical runtime-component target: $connector" >&2
        exit 2
        ;;
esac
reject_symlink_components "$RUNTIME_REPORT_OUTPUT_ROOT"
if [ -z "${RUNTIME_COMPONENT_ENV_SNAPSHOT:-}" ]; then
    RUNTIME_COMPONENT_ENV_SNAPSHOT=$(sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/reserve-runtime-env-snapshot.sh" "$RUNTIME_REPORT_OUTPUT_ROOT") || exit $?
    snapshot_reserved_here=1
else
    snapshot_reserved_here=0
fi
case "$RUNTIME_COMPONENT_ENV_SNAPSHOT" in
    "$RUNTIME_REPORT_OUTPUT_ROOT"/*) ;;
    *)
        echo "FAIL: canonical runtime environment snapshot must be under this connector build root: $RUNTIME_COMPONENT_ENV_SNAPSHOT" >&2
        exit 1
        ;;
esac
reject_symlink_components "$RUNTIME_COMPONENT_ENV_SNAPSHOT"
export RUNTIME_COMPONENT_ENV_SNAPSHOT

"$PYTHON" "$FRAMEWORK_ROOT/ci/checks/catalog/no_crs_baseline.py" select \
    --connector "$connector" \
    --capabilities "$CAPABILITIES_FILE" \
    --evidence-stage "$evidence_stage" \
    --artifact-profile "$NO_CRS_ARTIFACT_PROFILE" \
    --downstream-protocol "$selection_downstream_protocol" \
    --output "$PLAN"
if [ "${ON_DEMAND_TESTS:-0}" != 1 ]; then
    "$PYTHON" - "$CONNECTOR_ROOT" "$PLAN" "$connector" "$evidence_stage" <<'ACTIVE_PLAN'
import json
import sys
from pathlib import Path
root, plan_path = Path(sys.argv[1]), Path(sys.argv[2])
from modsecurity_connector_ci.lib.active_test_inventory import InventoryError, load_inventory
try:
    inventory = load_inventory(root)
    if sys.argv[4] != "minimal_runtime_smoke":
        raise InventoryError("specialist No-CRS catalogs require explicit ON_DEMAND_TESTS=1")
    execution_id = "runtime.no-crs." + sys.argv[3]
    matches = [item for item in inventory.executions if item["id"] == execution_id]
    if len(matches) != 1:
        raise InventoryError("No-CRS execution is absent from the authoritative inventory")
    expected = {case["id"].removeprefix(execution_id + ".") for case in matches[0]["cases"]}
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    selected = [item for item in plan["cases"] if item.get("selection_status") == "SELECTED"]
    actual = [item["case_id"] for item in selected]
    if (len(actual) != len(expected) or len(set(actual)) != len(actual)
            or set(actual) != expected
            or any(item.get("runner_case") != item["case_id"] + ".yaml" for item in selected)):
        raise InventoryError("Framework plan differs from the expanded Parent active inventory")
except (InventoryError, OSError, ValueError, KeyError) as error:
    raise SystemExit("FAIL: active No-CRS selection: " + str(error)) from error
ACTIVE_PLAN
fi
NO_CRS_SELECTED_CASES=$("$PYTHON" -c '
import json, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
print(" ".join(
    str(item["runner_case"]) for item in plan.get("cases", [])
    if item.get("selection_status") == "SELECTED" and item.get("runner_case")
))
' "$PLAN")
NO_CRS_SELECTED_CASE_IDS=$("$PYTHON" -c '
import json, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
print(" ".join(
    str(item["case_id"]) for item in plan.get("cases", [])
    if item.get("selection_status") == "SELECTED" and item.get("case_id")
))
' "$PLAN")
if [ "$NO_CRS_ARTIFACT_PROFILE" != full_lifecycle ] || \
   [ "$connector" = apache ] || [ "$connector" = nginx ]; then
    case " $NO_CRS_SELECTED_CASES " in
        *" allow_without_marker.yaml "*) ;;
        *) echo "FAIL: canonical plan does not select mandatory allow runner case" >&2; exit 1 ;;
    esac
    case " $NO_CRS_SELECTED_CASES " in
        *" deny_header_marker_403.yaml "*) ;;
        *) echo "FAIL: canonical plan does not select mandatory deny runner case" >&2; exit 1 ;;
    esac
else
    # A native profile that has no executable capability yet is still a useful
    # canonical record: it finalizes as NOT_EXECUTED/BLOCKED instead of being
    # silently rerouted through its compatibility implementation.
    echo "INFO: $connector/$FULL_LIFECYCLE_HOST_PROFILE has no mandatory compatibility-case requirement"
fi

case "$evidence_stage" in
    minimal_runtime_smoke) executed_target=runtime-smoke-$connector ;;
    no_crs_baseline) executed_target=no-crs-baseline-$connector ;;
    *)
        echo "FAIL: unsupported evidence stage: $evidence_stage" >&2
        exit 2
        ;;
esac
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    executed_target=$FULL_LIFECYCLE_EXECUTED_TARGET
fi

"$PYTHON" "$FRAMEWORK_ROOT/ci/checks/catalog/no_crs_baseline.py" init \
    --connector "$connector" \
    --capabilities "$CAPABILITIES_FILE" \
    --plan "$PLAN" \
    --run-dir "$RUN_DIR" \
    --connector-root "$CONNECTOR_ROOT" \
    --run-id "$NO_CRS_RUN_ID" \
    --evidence-stage "$evidence_stage" \
    --artifact-profile "$NO_CRS_ARTIFACT_PROFILE" \
    --downstream-protocol "$selection_downstream_protocol" \
    --host-profile "${FULL_LIFECYCLE_HOST_PROFILE:-default}" \
    --executed-target "$executed_target" \
    --host-version not_provisioned \
    --libmodsecurity-version not_provisioned

prepare_nginx_native_authority

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
set +e
env \
CONNECTOR_ROOT="$CONNECTOR_ROOT" \
FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
VERIFIED_RUN_ROOT="$CANONICAL_VERIFIED_RUN_ROOT" \
VERIFIED_BUILD_ROOT="$STAGE_BUILD_ROOT" \
VERIFIED_TMP_ROOT="$STAGE_TMP_ROOT" \
VERIFIED_LOG_ROOT="$STAGE_LOG_ROOT" \
VERIFIED_COMPONENT_CACHE="$VERIFIED_COMPONENT_CACHE" \
CACHE_ROOT="$CACHE_ROOT" \
CONNECTOR_COMPONENT_CACHE="$SHARED_COMPONENT_CACHE" \
BUILD_ROOT="$STAGE_BUILD_ROOT" \
TMP_ROOT="$STAGE_TMP_ROOT" \
LOG_ROOT="$STAGE_LOG_ROOT" \
RESULTS_DIR="$STAGE_RESULTS_DIR" \
RUNTIME_ROOT="$STAGE_RUNTIME_ROOT" \
RUNTIME_BASE="$STAGE_RUNTIME_ROOT" \
RUNTIME_REPORT_OUTPUT_ROOT="$RUNTIME_REPORT_OUTPUT_ROOT" \
RUNTIME_COMPONENT_TARGET="$canonical_runtime_component_target" \
RUNTIME_COMPONENT_ENV_SNAPSHOT="$RUNTIME_COMPONENT_ENV_SNAPSHOT" \
APACHE_RUNTIME_LOG_DIR="$HOST_RUNTIME_ROOT/apache-runtime" \
APACHE_CASE_OUTPUT_ROOT="$HOST_RUNTIME_ROOT" \
NGINX_HARNESS_PARENT="$STAGE_NGINX_HARNESS_PARENT" \
NGINX_HARNESS_WORK_ROOT="$NGINX_RUN_ROOT" \
NGINX_DOCROOT_PROJECTION="$NGINX_DOCROOT_PROJECTION" \
NGINX_DOCROOT_PROJECTION_PARENT="${NGINX_DOCROOT_PROJECTION_PARENT:-}" \
NGINX_DOCROOT_PROJECTION_ROOT="${NGINX_DOCROOT_PROJECTION_ROOT:-}" \
RUNTIME_EVENT_LOG_PATH="$STAGE_RUNTIME_ROOT/events.jsonl" \
HAPROXY_HTX_RUNTIME_ROOT="$STAGE_RUNTIME_ROOT" \
HAPROXY_HTX_EVENT_LOG_PATH="$STAGE_RUNTIME_ROOT/events.jsonl" \
ENVOY_RUNTIME_ROOT="$HOST_RUNTIME_ROOT" \
ENVOY_CONFIG_ROOT="$HOST_RUNTIME_ROOT/config" \
ENVOY_LOG_ROOT="$HOST_LOG_ROOT" \
ENVOY_RESULT_ROOT="$HOST_RUNTIME_ROOT" \
ENVOY_EXT_PROC_RUNTIME_ROOT="$HOST_RUNTIME_ROOT" \
ENVOY_EXT_PROC_EVENT_LOG_PATH="$HOST_RUNTIME_ROOT/events.jsonl" \
TRAEFIK_CONFIG_ROOT="$TRAEFIK_RUNTIME_ROOT/config" \
TRAEFIK_LOG_ROOT="$HOST_LOG_ROOT/traefik" \
TRAEFIK_RESULT_ROOT="$TRAEFIK_RUNTIME_ROOT" \
TRAEFIK_NATIVE_RUNTIME_ROOT="$TRAEFIK_RUNTIME_ROOT" \
TRAEFIK_FIRST_BYTE_EVIDENCE_ROOT="$CONNECTOR_RUN_ROOT" \
TRAEFIK_BUILD_ROOT="$CONNECTOR_BUILD_ROOT/traefik-connector" \
TRAEFIK_CONNECTOR_BUILD_DIR="$CONNECTOR_BUILD_ROOT/traefik-connector" \
TRAEFIK_CONNECTOR_BIN="$CONNECTOR_BUILD_ROOT/traefik-connector/traefik-forwardauth" \
TRAEFIK_CONNECTOR_START_ROOT="$CONNECTOR_RUN_ROOT/traefik-start-smoke" \
TRAEFIK_NATIVE_MIDDLEWARE_BUILD_DIR="$CONNECTOR_BUILD_ROOT/traefik-native-middleware" \
TRAEFIK_CONNECTOR_RESULT_ROOT="$TRAEFIK_RUNTIME_ROOT" \
LIGHTTPD_CONFIG_ROOT="$LIGHTTPD_RUNTIME_ROOT/config" \
LIGHTTPD_LOG_ROOT="$HOST_LOG_ROOT/lighttpd" \
LIGHTTPD_RESULT_ROOT="$LIGHTTPD_RUNTIME_ROOT" \
LIGHTTPD_CONNECTOR_BUILD_ROOT="$CONNECTOR_BUILD_ROOT/lighttpd-connector" \
LIGHTTPD_MODULE_DIR="$CONNECTOR_BUILD_ROOT/lighttpd-connector/modules" \
LIGHTTPD_SMOKE_DIR="$LIGHTTPD_RUNTIME_ROOT" \
LIGHTTPD_PATCHED_ROOT="$HOST_RUNTIME_ROOT/lighttpd-patched" \
LIGHTTPD_PATCHED_SMOKE_DIR="$LIGHTTPD_RUNTIME_ROOT" \
RULES_FILE="$NO_CRS_RULES_FILE" \
MSCONNECTOR_RULES_FILE="$NO_CRS_RULES_FILE" \
NO_CRS_RULES_FILE="$NO_CRS_RULES_FILE" \
NO_CRS_SELECTED_CASES="$NO_CRS_SELECTED_CASES" \
NO_CRS_SELECTED_CASE_IDS="$NO_CRS_SELECTED_CASE_IDS" \
NO_CRS_ARTIFACT_PROFILE="$NO_CRS_ARTIFACT_PROFILE" \
NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR="$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" \
FULL_LIFECYCLE_HOST_PROFILE="$FULL_LIFECYCLE_HOST_PROFILE" \
FULL_LIFECYCLE_EXECUTED_TARGET="$FULL_LIFECYCLE_EXECUTED_TARGET" \
FULL_LIFECYCLE_EVIDENCE_OUTPUT="$STAGE_FIRST_BYTE_EVIDENCE_OUTPUT" \
FIVE_CONNECTOR_PROFILE="$FIVE_CONNECTOR_PROFILE" \
FIVE_CONNECTOR_PARENT_COMMIT="$FIVE_CONNECTOR_PARENT_COMMIT" \
FIVE_CONNECTOR_FRAMEWORK_COMMIT="$FIVE_CONNECTOR_FRAMEWORK_COMMIT" \
MSCONNECTOR_EXPECTED_RULE_ID="$EXPECTED_RULE_ID" \
NO_CRS_RUN_ID="$NO_CRS_RUN_ID" \
sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-connector-stage.sh" "$connector" "$evidence_stage" \
    >"$LOG_DIR/stdout.log" 2>"$LOG_DIR/stderr.log"
stage_rc=$?
set -e
ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PROCESS_CLEANUP_LOG=$LOG_DIR/process-cleanup.log
cleanup_status=passed
if ps -eo pid=,comm=,args= | MSCONNECTOR_PROCESS_ROOT="$CONNECTOR_RUN_ROOT" awk '
    BEGIN { root=ENVIRON["MSCONNECTOR_PROCESS_ROOT"] }
    index($0, root) > 0 && ($2 ~ /^(httpd|apache2|nginx|haproxy|envoy|traefik|lighttpd|spoa|msconnector)/ || ($2 ~ /^python/ && $0 ~ /serve-upstream/)) { print $1, $2; found=1 }
    END { exit(found ? 1 : 0) }
' > "$PROCESS_CLEANUP_LOG"; then
    printf 'none\n' > "$PROCESS_CLEANUP_LOG"
else
    cleanup_rc=$?
    cleanup_status=failed
    if [ "$cleanup_rc" -eq 1 ] && [ -s "$PROCESS_CLEANUP_LOG" ]; then
        echo "FAIL: connector processes remain after canonical run; see $PROCESS_CLEANUP_LOG" >&2
        stage_rc=1
    else
        echo "FAIL: unable to verify connector process cleanup" >&2
        printf 'process-check-failed rc=%s\n' "$cleanup_rc" > "$PROCESS_CLEANUP_LOG"
        stage_rc=1
    fi
fi

# Apache and NGINX have native proxy/filter paths with synchronized barrier
# support. Run their additional proof separately so the client can be observed
# while the upstream is deliberately paused. Other selected host routes retain
# a diagnostic-only barrier until they publish equivalent real-host evidence.
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    case "$connector" in
        apache|nginx)
            run_native_first_byte=1
            if [ "$connector" = nginx ] && \
               [ "${NGINX_DOWNSTREAM_PROTOCOL:-http1}" != http1 ]; then
                # The synchronized helper is an H1-only proof. A selected
                # H2/H3 listener must not inherit its H1 result or turn its
                # honest non-execution into a runner failure.
                run_native_first_byte=0
                echo "INFO: skipping H1 native first-byte helper for NGINX downstream ${NGINX_DOWNSTREAM_PROTOCOL}" >&2
            fi
            if [ "$run_native_first_byte" -eq 1 ]; then
                native_first_byte_rc=0
                env \
                CONNECTOR_ROOT="$CONNECTOR_ROOT" \
                FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
                VERIFIED_RUN_ROOT="$CANONICAL_VERIFIED_RUN_ROOT" \
                BUILD_ROOT="$STAGE_BUILD_ROOT" \
                VERIFIED_BUILD_ROOT="$STAGE_BUILD_ROOT" \
                RUNTIME_REPORT_OUTPUT_ROOT="$RUNTIME_REPORT_OUTPUT_ROOT" \
                RESULTS_DIR="$STAGE_RESULTS_DIR" \
                HOST_RUNTIME_ROOT="$STAGE_RUNTIME_ROOT" \
                HOST_LOG_ROOT="$HOST_LOG_ROOT" \
                SYNCHRONIZED_UPSTREAM_CONTROL_ROOT="$CONNECTOR_RUN_ROOT" \
                NO_CRS_RULES_FILE="$NO_CRS_RULES_FILE" \
                FULL_LIFECYCLE_EVIDENCE_OUTPUT="$FIRST_BYTE_EVIDENCE" \
                SKIP_RUNTIME_COMPONENT_PREPARE=1 \
                sh "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-native-first-byte.sh" "$connector" || native_first_byte_rc=$?
                if [ "$native_first_byte_rc" -ne 0 ]; then
                    stage_rc=$native_first_byte_rc
                fi
            fi
            ;;
        *) ;;
    esac
fi

source_results=
source_result=
source_events=
source_first_byte_results=$STAGE_RESULTS_DIR/$connector-first-byte-results.jsonl
case "$connector" in
    apache|nginx)
        source_results=$STAGE_RESULTS_DIR/$connector-results.jsonl
        source_result=$STAGE_RESULTS_DIR/$connector-summary.json
        ;;
    haproxy)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            source_result=$STAGE_RUNTIME_ROOT/runtime-summary.txt
            source_events=$STAGE_RUNTIME_ROOT/events.jsonl
        else
            source_results=$STAGE_RESULTS_DIR/$connector-results.jsonl
            source_result=$STAGE_RESULTS_DIR/$connector-summary.json
        fi
        ;;
    envoy)
        source_result=$HOST_RUNTIME_ROOT/runtime-summary.txt
        source_events=$HOST_RUNTIME_ROOT/events.jsonl
        ;;
    traefik)
        source_result=$TRAEFIK_RUNTIME_ROOT/result.json
        source_events=$TRAEFIK_RUNTIME_ROOT/logs/events.jsonl
        # The host writer is intentionally confined to the private build root,
        # while the collector is intentionally confined to the raw run. Move
        # only the two fixed Traefik producer artifacts with descriptor-based
        # no-follow validation; never widen the collector source boundary.
        "$PYTHON" "$TRAEFIK_ARTIFACT_STAGER" \
            --build-root "$STAGE_BUILD_ROOT" \
            --raw-root "$RAW_DIR" || {
                echo "FAIL: unable to stage Traefik runtime artifacts into the raw run" >&2
                exit 1
            }
        source_result=$RAW_DIR/traefik-source/result.json
        source_events=$RAW_DIR/traefik-source/events.jsonl
        ;;
    lighttpd)
        source_results=$LIGHTTPD_RUNTIME_ROOT/results.jsonl
        source_result=$LIGHTTPD_RUNTIME_ROOT/runtime-summary.txt
        source_events=$LIGHTTPD_RUNTIME_ROOT/events.jsonl
        ;;
    *)
        echo "FAIL: unsupported connector source-result mapping: $connector" >&2
        exit 2
        ;;
esac

set -- \
    --connector "$connector" \
    --stage-rc "$stage_rc" \
    --expected-rule-id "$EXPECTED_RULE_ID" \
    --catalog "$FRAMEWORK_ROOT/tests/cases/no-crs-baseline/catalog.json" \
    --framework-root "$FRAMEWORK_ROOT" \
    --stdout "$LOG_DIR/stdout.log" \
    --stderr "$LOG_DIR/stderr.log" \
    --allowed-source-root "$RAW_DIR" \
    --allowed-log-root "$LOG_DIR" \
    --scrub-source-events \
    --source-event-scrub-log "$SOURCE_EVENT_SCRUB_LOG" \
    --events-output "$NORMALIZED_EVENTS" \
    --output "$SOURCE_RESULT"
if [ "$five_connector_profile_enabled" -eq 1 ]; then
    set -- "$@" --five-connector-profile "$FIVE_CONNECTOR_PROFILE"
fi
if [ "$NGINX_NATIVE_AUTHORITY_ENABLED" -eq 1 ]; then
    # Keep generic harness and first-byte logs outside the native bundle
    # authority so their normal collection/scrubbing cannot touch originals.
    set -- "$@" --allowed-native-operation-root "$STAGE_BUILD_ROOT/host-runtime/native-operations-$NO_CRS_RUN_ID"
fi
if [ -n "$source_result" ] && [ -f "$source_result" ]; then
    set -- "$@" --source-result "$source_result"
fi
if [ -n "$source_results" ] && [ -f "$source_results" ]; then
    set -- "$@" --source-results-jsonl "$source_results"
fi
if [ -f "$source_first_byte_results" ]; then
    set -- "$@" --source-results-jsonl "$source_first_byte_results"
fi
if [ -n "$source_events" ] && [ -f "$source_events" ]; then
    set -- "$@" --source-events "$source_events"
fi
"$PYTHON" "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/collect-no-crs-source.py" "$@"

# Raw host logs remain in the disposable per-run log tree. Canonical evidence
# receives only bounded, sentinel-free diagnostics plus a metadata-only host
# summary, so body fixtures and credentials cannot be retained accidentally.
"$PYTHON" "$LOG_SANITIZER" --input "$LOG_DIR/stdout.log" \
    --output "$CANONICAL_STDOUT_LOG" \
    --runtime-root "$CANONICAL_VERIFIED_RUN_ROOT" \
    --label "${connector}-stage-stdout"
"$PYTHON" "$LOG_SANITIZER" --input "$LOG_DIR/stderr.log" \
    --output "$CANONICAL_STDERR_LOG" \
    --runtime-root "$CANONICAL_VERIFIED_RUN_ROOT" \
    --label "${connector}-stage-stderr"
{
    printf 'connector=%s\n' "$connector"
    printf 'evidence_stage=%s\n' "$evidence_stage"
    printf 'artifact_profile=%s\n' "$NO_CRS_ARTIFACT_PROFILE"
    printf 'host_profile=%s\n' "${FULL_LIFECYCLE_HOST_PROFILE:-default}"
    printf 'executed_target=%s\n' "$executed_target"
    printf 'stage_exit_code=%s\n' "$stage_rc"
    printf 'process_cleanup_log=%s\n' "$(basename "$PROCESS_CLEANUP_LOG")"
    "$PYTHON" - "$LOG_DIR/stdout.log" "$LOG_DIR/stderr.log" <<'PY'
import hashlib
import sys
from pathlib import Path

for label, value in zip(("stage_stdout", "stage_stderr"), sys.argv[1:]):
    raw = Path(value).read_bytes() if Path(value).is_file() else b""
    print(f"{label}_sha256={hashlib.sha256(raw).hexdigest()}")
    print(f"{label}_bytes={len(raw)}")
PY
} > "$CANONICAL_HOST_LOG"
FIVE_CONNECTOR_PROFILE_RECEIPT=
if [ "$five_connector_profile_enabled" -eq 1 ]; then
    FIVE_CONNECTOR_PROFILE_RECEIPT=$CONNECTOR_RUN_ROOT/five-connector-profile-receipt.json
    "$PYTHON" "$FIVE_CONNECTOR_PROFILE_RESOLVER" \
        --profile "$FIVE_CONNECTOR_PROFILE" \
        --write-receipt \
        --runtime-root "$CONNECTOR_RUN_ROOT" \
        --output "$FIVE_CONNECTOR_PROFILE_RECEIPT" \
        --connector "$connector" \
        --run-id "$NO_CRS_RUN_ID" \
        --connector-commit "$FIVE_CONNECTOR_PARENT_COMMIT" \
        --framework-commit "$FIVE_CONNECTOR_FRAMEWORK_COMMIT" \
        --cleanup-status "$cleanup_status"
fi
if [ ! -f "$NORMALIZED_EVENTS" ]; then
    : > "$NORMALIZED_EVENTS"
fi
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    "$PYTHON" "$TRANSPORT_ARTIFACT_WRITER" \
        --connector "$connector" \
        --run-id "$NO_CRS_RUN_ID" \
        --runtime-root "$CONNECTOR_RUN_ROOT" \
        --events "$NORMALIZED_EVENTS" \
        --output-dir "$TRANSPORT_ARTIFACT_DIR" || {
            echo "FAIL: unable to write payload-free transport lifecycle artifacts" >&2
            exit 1
        }
    for transport_artifact in \
        "$CLIENT_TRANSPORT_LOG" \
        "$UPSTREAM_TRANSPORT_LOG" \
        "$TRANSPORT_LOG" \
        "$CLEANUP_TRANSPORT_LOG" \
        "$TRANSPORT_OBSERVATIONS_ARTIFACT" \
        "$CONNECTION_LIFECYCLE_ARTIFACT" \
        "$BARRIER_EVENTS_ARTIFACT"; do
        if [ ! -f "$transport_artifact" ] || [ -L "$transport_artifact" ]; then
            echo "FAIL: required transport artifact is missing or unsafe: $transport_artifact" >&2
            exit 1
        fi
    done
fi
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    if [ -n "$FIRST_BYTE_EVIDENCE_SOURCE" ]; then
        case "$FIRST_BYTE_EVIDENCE_SOURCE" in
            /*) ;;
            *) echo "FAIL: FIRST_BYTE_EVIDENCE_SOURCE must be absolute" >&2; exit 1 ;;
        esac
        case "$FIRST_BYTE_EVIDENCE_SOURCE" in
            "$RAW_DIR"/*) ;;
            *) echo "FAIL: FIRST_BYTE_EVIDENCE_SOURCE must remain inside this raw run: $FIRST_BYTE_EVIDENCE_SOURCE" >&2; exit 1 ;;
        esac
        [ ! -L "$FIRST_BYTE_EVIDENCE_SOURCE" ] || {
            echo "FAIL: FIRST_BYTE_EVIDENCE_SOURCE must not be a symlink" >&2
            exit 1
        }
        [ -f "$FIRST_BYTE_EVIDENCE_SOURCE" ] || {
            echo "FAIL: FIRST_BYTE_EVIDENCE_SOURCE is missing: $FIRST_BYTE_EVIDENCE_SOURCE" >&2
            exit 1
        }
        if [ "$FIRST_BYTE_EVIDENCE_SOURCE" != "$FIRST_BYTE_EVIDENCE" ]; then
            cp "$FIRST_BYTE_EVIDENCE_SOURCE" "$FIRST_BYTE_EVIDENCE"
        fi
    elif [ ! -f "$FIRST_BYTE_EVIDENCE" ]; then
        # Preserve an explicit synthetic barrier observation when no connector
        # harness supplied a real-host one.  The Framework records its origin
        # and refuses to promote either low-latency capability from it.
        "$PYTHON" "$SYNCHRONIZED_UPSTREAM" \
            --control-root "$CONNECTOR_RUN_ROOT" \
            --output "$FIRST_BYTE_EVIDENCE" \
            >"$LOG_DIR/synchronized-upstream.stdout.log" \
            2>"$LOG_DIR/synchronized-upstream.stderr.log"
        [ -f "$FIRST_BYTE_EVIDENCE" ] || {
            echo "FAIL: synchronized first-byte diagnostic did not produce evidence" >&2
            exit 1
        }
    fi
fi

host_version=not_provisioned
host_binary=
runtime_env=$RUNTIME_COMPONENT_ENV_SNAPSHOT
if [ -s "$runtime_env" ]; then
    snapshot_path_valid=1
    case "$runtime_env" in
        "$CONNECTOR_BUILD_ROOT/runtime-component-reports"/*) ;;
        *)
            echo "FAIL: canonical runtime environment snapshot escaped its connector build root: $runtime_env" >&2
            stage_rc=1
            snapshot_path_valid=0
            ;;
    esac
    if [ "$snapshot_path_valid" -eq 1 ]; then
        reject_symlink_components "$runtime_env"
        # This is the exact invocation-local file passed to run-connector-stage,
        # not the mutable shared Cache-v2 compatibility export.
        # shellcheck disable=SC1090
        . "$runtime_env"
        case "$canonical_runtime_component_target:${RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET:-}" in
            apache:apache|nginx:nginx|haproxy:haproxy|shared:shared|shared:all) ;;
            *)
                echo "FAIL: canonical runtime environment snapshot target mismatch: requested=$canonical_runtime_component_target snapshot=${RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET:-unset}" >&2
                stage_rc=1
                ;;
        esac
        if [ "${RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE:-}" != "$SHARED_COMPONENT_CACHE" ]; then
            echo "FAIL: canonical runtime environment snapshot cache mismatch: expected=$SHARED_COMPONENT_CACHE snapshot=${RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE:-unset}" >&2
            stage_rc=1
        fi
    fi
elif [ "$stage_rc" -eq 0 ]; then
    echo "FAIL: canonical stage completed without its invocation-local runtime environment snapshot: $runtime_env" >&2
    stage_rc=1
elif [ "$snapshot_reserved_here" -eq 1 ]; then
    # Full-lifecycle BLOCKED profiles may exit before any component resolver
    # runs.  Do not leave their empty reservation behind as if it were usable
    # evidence.
    rm -f "$runtime_env"
fi
# A snapshot may supply toolchain paths, but never gets to redirect the
# resolver-selected cache or the connector-local build root used for inventory.
CONNECTOR_COMPONENT_CACHE=$SHARED_COMPONENT_CACHE
RUNTIME_COMPONENT_ENV_SNAPSHOT=$runtime_env
if [ "$NGINX_NATIVE_AUTHORITY_ENABLED" -eq 1 ] && \
   [ "${NGINX_PREFIX:-}" != "$NGINX_NATIVE_AUTHORITY_PREFIX" ]; then
    echo "FAIL: runtime snapshot NGINX_PREFIX differs from sealed native authority prefix" >&2
    stage_rc=1
fi
# Store only an allowlisted hash inventory for effective configuration.  Raw
# rules and host configuration can contain fixture payloads or credentials and
# must remain in the disposable run root.
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    set -- \
        --connector "$connector" \
        --run-id "$NO_CRS_RUN_ID" \
        --runtime-root "$CONNECTOR_RUN_ROOT" \
        --config-source-root "$CONNECTOR_BUILD_ROOT" \
        --framework-root "$FRAMEWORK_ROOT" \
        --effective-config-dir "$EFFECTIVE_CONFIG_ARTIFACT_DIR" \
        --config-file "capabilities.json=$CAPABILITIES_FILE" \
        --config-file "rules/no-crs-baseline.conf=$NO_CRS_RULES_FILE"
    if [ -s "$runtime_env" ]; then
        set -- "$@" --config-file "runtime-components.env=$runtime_env"
    fi
    "$PYTHON" "$TRANSPORT_ARTIFACT_WRITER" "$@" || {
        echo "FAIL: unable to write effective configuration inventory" >&2
        exit 1
    }
    if [ ! -f "$EFFECTIVE_CONFIG_MANIFEST" ] || [ -L "$EFFECTIVE_CONFIG_MANIFEST" ]; then
        echo "FAIL: effective configuration inventory is missing or unsafe" >&2
        exit 1
    fi
fi
# Inventory must describe this connector's isolated build root even if a
# concurrent connector invocation generated another shared compatibility file.
BUILD_ROOT=$CONNECTOR_BUILD_ROOT
case "$connector" in
    apache) host_binary=${APACHE_HTTPD:-$BUILD_ROOT/apache-runtime/httpd/bin/httpd} ;;
    nginx) host_binary=${MRTS_NATIVE_NGINX_BIN:-$BUILD_ROOT/nginx-runtime/nginx/sbin/nginx} ;;
    haproxy)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            host_binary=$STAGE_RUNTIME_ROOT/overlay-build/worktree/haproxy
        else
            host_binary=${HAPROXY_BIN:-$BUILD_ROOT/haproxy-runtime/haproxy/sbin/haproxy}
        fi
        ;;
    envoy) host_binary=$CONNECTOR_COMPONENT_CACHE/envoy/bin/envoy ;;
    # The native lifecycle may deliberately provide a freshly staged pinned
    # binary outside the reusable component cache.  Record the version of the
    # binary that actually executed the host, not merely the cache default.
    traefik)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            host_binary=${TRAEFIK_BIN:-$CONNECTOR_COMPONENT_CACHE/traefik/bin/traefik}
        else
            # The stage child provisions the pinned archive into this exact
            # connector build root. Its exported TRAEFIK_BIN cannot propagate
            # back to this parent; inherited/cache paths describe another host.
            host_binary=$("$PYTHON" "$TRAEFIK_HOST_BINARY_RESOLVER" \
                --build-root "$CONNECTOR_BUILD_ROOT") || {
                echo "INFO: staged Traefik host binary is unavailable or unsafe; host version remains not_provisioned" >&2
                host_binary=
            }
        fi
        ;;
    lighttpd)
        if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
            host_binary=$HOST_RUNTIME_ROOT/lighttpd-patched/stage/bin/lighttpd
        else
            # Only record the version of the fixed connector-local staged
            # binary. An absent or unsafe staged file deliberately leaves the
            # host version at not_provisioned; inherited LIGHTTPD_BIN values,
            # shared-cache paths, and system fallbacks are never consumed.
            host_binary=$("$PYTHON" "$LIGHTTPD_HOST_BINARY_RESOLVER" \
                --build-root "$CONNECTOR_BUILD_ROOT") || {
                echo "INFO: staged Lighttpd host binary is unavailable or unsafe; host version remains not_provisioned" >&2
                host_binary=
            }
        fi
        ;;
    *)
        echo "FAIL: unsupported connector host-binary mapping: $connector" >&2
        exit 2
        ;;
esac
if [ -n "$host_binary" ] && [ -x "$host_binary" ]; then
    case "$connector" in
        apache)
            apache_runtime_lib=$(dirname "$(dirname "$host_binary")")/lib
            if apache_version_output=$(LD_LIBRARY_PATH="$apache_runtime_lib:${MODSECURITY_LIB_DIR:-}:${LD_LIBRARY_PATH:-}" \
                "$host_binary" -v); then
                host_version=$(printf '%s\n' "$apache_version_output" | "$PYTHON" -c '
import re
import sys

versions = [line.strip() for line in sys.stdin if line.strip().startswith("Server version:")]
if len(versions) != 1 or not re.fullmatch(
    r"Server version: Apache/\d+\.\d+\.\d+(?:[ \t]+\([^\r\n]*\))?", versions[0], flags=re.ASCII
):
    raise SystemExit("FAIL: Apache host did not report one valid native Server version")
print(versions[0])
') || exit 2
            else
                apache_version_rc=$?
                echo "FAIL: Apache host version command failed (rc=$apache_version_rc)" >&2
                exit "$apache_version_rc"
            fi
            ;;
        nginx) host_version=$($host_binary -v 2>&1 | sed -n "$FIRST_NONEMPTY_OUTPUT_LINE_SED_SCRIPT") ;;
        haproxy) host_version=$($host_binary -v 2>&1 | sed -n "$FIRST_NONEMPTY_OUTPUT_LINE_SED_SCRIPT") ;;
        envoy) host_version=$($host_binary --version 2>&1 | sed -n "$FIRST_NONEMPTY_OUTPUT_LINE_SED_SCRIPT") ;;
        traefik) host_version=$("$host_binary" version 2>&1 | sed -n "$FIRST_NONEMPTY_OUTPUT_LINE_SED_SCRIPT") ;;
        lighttpd) host_version=$($host_binary -v 2>&1 | sed -n "$FIRST_NONEMPTY_OUTPUT_LINE_SED_SCRIPT") ;;
        *)
            echo "FAIL: unsupported connector host-version mapping: $connector" >&2
            exit 2
            ;;
    esac
fi
[ -n "$host_version" ] || host_version=unknown

libmodsecurity_version=not_provisioned
component_manifest=$CONNECTOR_COMPONENT_CACHE/manifest.json
if [ -f "$component_manifest" ]; then
    libmodsecurity_version=$($PYTHON - "$component_manifest" <<'PY'
import json
import sys

try:
    component = json.load(open(sys.argv[1], encoding="utf-8")).get("modsecurity", {})
except (OSError, ValueError):
    component = {}
if component.get("status") in {"built", "reused", "present"} and component.get("actual_sha") and component.get("build_id"):
    print(f"git:{component['actual_sha']};build:{component['build_id']}")
else:
    print("not_provisioned")
PY
    )
fi

# Full-lifecycle engine sidecars are an inventory of the exact current raw
# host run.  They do not feed capability selection or promotion: canonical
# PASS still requires the normal transaction-bound host event evidence.
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ] && [ "$stage_rc" -eq 0 ]; then
    modsecurity_build_id=${MODSECURITY_BUILD_ID:-}
    case "$modsecurity_build_id" in
        ""|.|..|*[!A-Za-z0-9_-]*)
            echo "FAIL: full-lifecycle modsecurity build identity is unsafe" >&2
            exit 1
            ;;
        *)
            # The rejection pattern above leaves only a non-empty managed-cache
            # identifier consisting of ASCII letters, digits, underscores, or dashes.
            ;;
    esac
    modsecurity_prefix=$CONNECTOR_COMPONENT_CACHE/prefix/modsecurity/$modsecurity_build_id
    modsecurity_library_root=$modsecurity_prefix/lib
    if [ "${MODSECURITY_PREFIX:-}" != "$modsecurity_prefix" ] || \
       [ "${MODSECURITY_LIB_DIR:-}" != "$modsecurity_library_root" ]; then
        echo "FAIL: full-lifecycle library path is not bound to the managed modsecurity cache entry" >&2
        exit 1
    fi
    libmodsecurity_library=$modsecurity_library_root/libmodsecurity.so
    if [ ! -f "$libmodsecurity_library" ]; then
        echo "FAIL: full-lifecycle engine library is unavailable for provenance: $libmodsecurity_library" >&2
        exit 1
    fi
    "$PYTHON" "$ENGINE_ARTIFACT_WRITER" \
        --connector "$connector" \
        --source-result "$SOURCE_RESULT" \
        --source-events "$NORMALIZED_EVENTS" \
        --rules-file "$NO_CRS_RULES_FILE" \
        --framework-root "$FRAMEWORK_ROOT" \
        --libmodsecurity-version "$libmodsecurity_version" \
        --libmodsecurity-library "$libmodsecurity_library" \
        --libmodsecurity-library-root "$modsecurity_library_root" \
        --stage-exit-code "$stage_rc" \
        --runtime-root "$CONNECTOR_RUN_ROOT" \
        --transport-lifecycle "$CONNECTION_LIFECYCLE_ARTIFACT" \
        --output-dir "$ENGINE_ARTIFACT_DIR" || {
            echo "FAIL: unable to write full-lifecycle engine artifacts" >&2
            exit 1
        }
    for engine_artifact in \
        "$ENGINE_VERSION_ARTIFACT" \
        "$ENGINE_LIBRARY_SHA256_ARTIFACT" \
        "$RULESET_SHA256_ARTIFACT" \
        "$TRANSACTION_COUNTS_ARTIFACT" \
        "$LIFECYCLE_COUNTERS_ARTIFACT"; do
        if [ ! -s "$engine_artifact" ]; then
            echo "FAIL: required full-lifecycle engine artifact is missing: $engine_artifact" >&2
            exit 1
        fi
    done
fi

set -- \
    finalize \
    --run-dir "$RUN_DIR" \
    --connector-root "$CONNECTOR_ROOT" \
    --capabilities "$CAPABILITIES_FILE" \
    --source-result "$SOURCE_RESULT" \
    --stdout-log "$CANONICAL_STDOUT_LOG" \
    --stderr-log "$CANONICAL_STDERR_LOG" \
    --source-log "process_cleanup=$PROCESS_CLEANUP_LOG" \
    --source-log "source_event_scrub=$SOURCE_EVENT_SCRUB_LOG" \
    --stage-rc "$stage_rc" \
    --host-version "$host_version" \
    --libmodsecurity-version "$libmodsecurity_version" \
    --started-at "$started_at" \
    --ended-at "$ended_at"
if [ "$five_connector_profile_enabled" -eq 1 ]; then
    set -- "$@" --source-log "five_connector_profile_receipt=$FIVE_CONNECTOR_PROFILE_RECEIPT"
fi
if [ "$NGINX_NATIVE_AUTHORITY_ENABLED" -eq 1 ]; then
    set -- "$@" --native-operation-authority "$NGINX_NATIVE_AUTHORITY"
fi
if [ -n "$FULL_LIFECYCLE_STAGE_REASON" ]; then
    set -- "$@" --stage-reason "$FULL_LIFECYCLE_STAGE_REASON"
fi
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ] || [ -s "$NORMALIZED_EVENTS" ]; then
    set -- "$@" --source-events "$NORMALIZED_EVENTS"
fi
if [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then
    set -- "$@" --host-log "$CANONICAL_HOST_LOG" \
        --first-byte-evidence "$FIRST_BYTE_EVIDENCE" \
        --source-artifact "client_log=$CLIENT_TRANSPORT_LOG" \
        --source-artifact "upstream_log=$UPSTREAM_TRANSPORT_LOG" \
        --source-artifact "transport_log=$TRANSPORT_LOG" \
        --source-artifact "cleanup_log=$CLEANUP_TRANSPORT_LOG" \
        --source-artifact "transport_observations=$TRANSPORT_OBSERVATIONS_ARTIFACT" \
        --source-artifact "connection_lifecycle=$CONNECTION_LIFECYCLE_ARTIFACT" \
        --source-artifact "barrier_events=$BARRIER_EVENTS_ARTIFACT" \
        --source-artifact "effective_config=$EFFECTIVE_CONFIG_ARTIFACT_DIR"
    if [ "$stage_rc" -eq 0 ]; then
        set -- "$@" \
            --source-artifact "engine_version=$ENGINE_VERSION_ARTIFACT" \
            --source-artifact "engine_library_sha256=$ENGINE_LIBRARY_SHA256_ARTIFACT" \
            --source-artifact "ruleset_sha256=$RULESET_SHA256_ARTIFACT" \
            --source-artifact "transaction_counts=$TRANSACTION_COUNTS_ARTIFACT" \
            --source-artifact "lifecycle_counters=$LIFECYCLE_COUNTERS_ARTIFACT"
    fi
fi
if [ -n "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" ]; then
    if [ ! -d "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" ] || \
       [ -L "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" ]; then
        if [ "$protocol_client_artifact_optional" = 1 ]; then
            echo "INFO: optional protocol client did not publish a bundle; no protocol capability is promoted" >&2
            protocol_client_artifact_dir=
        else
            echo "FAIL: protocol client artifact directory is missing or unsafe" >&2
            exit 1
        fi
    else
        reject_symlink_components "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR"
        protocol_client_artifact_dir=$("$PYTHON" - \
            "$NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR" "$RAW_DIR" <<'PY'
import sys
from pathlib import Path

candidate = Path(sys.argv[1]).resolve(strict=True)
raw_root = Path(sys.argv[2]).resolve(strict=True)
if candidate == raw_root or raw_root not in candidate.parents:
    raise SystemExit("protocol client artifact directory escaped the current raw run")
print(candidate)
PY
        ) || {
            echo "FAIL: protocol client artifact directory escaped the current raw run" >&2
            exit 1
        }
    fi
else
    protocol_client_artifact_dir=
fi
if [ -n "$protocol_client_artifact_dir" ]; then
    set -- "$@" --protocol-client-artifact-dir "$protocol_client_artifact_dir"
fi

set +e
"$PYTHON" "$FRAMEWORK_ROOT/ci/checks/catalog/no_crs_baseline.py" "$@"
finalize_rc=$?
set -e
if [ "$finalize_rc" -ne 0 ]; then
    exit "$finalize_rc"
fi
FINAL_RESULT=$EVIDENCE_ROOT/$connector/$NO_CRS_RUN_ID/result.json
HOSTRUNTIME_RECORD=$EVIDENCE_ROOT/$connector/$NO_CRS_RUN_ID/hostruntime-record.json
HOSTRUNTIME_SUMMARY=$EVIDENCE_ROOT/$connector/$NO_CRS_RUN_ID/hostruntime-summary.md
if [ -f "$FINAL_RESULT" ]; then
    "$PYTHON" "$HOSTRUNTIME_RECORD_WRITER" \
        --result "$FINAL_RESULT" \
        --manifest "$EVIDENCE_ROOT/$connector/$NO_CRS_RUN_ID/manifest.json" \
        --output "$HOSTRUNTIME_RECORD" \
        --summary "$HOSTRUNTIME_SUMMARY" \
        --runtime-root "$CANONICAL_VERIFIED_RUN_ROOT" \
        --connector "$connector" \
        --profile "${FULL_LIFECYCLE_HOST_PROFILE:-$NO_CRS_ARTIFACT_PROFILE}" \
        --runtime-lock-id "${HOSTRUNTIME_LOCK_ID:-}" \
        --expected-version "${HOSTRUNTIME_EXPECTED_VERSION:-}" \
        --actual-version "$host_version" || {
        echo "FAIL: unable to write hostruntime lifecycle record" >&2
        exit 1
    }
else
    echo "BLOCKED: finalized result is missing; no hostruntime record was promoted" >&2
fi
latest_file=$EVIDENCE_ROOT/$connector/latest-run-id
reject_symlink_components "$latest_file"
latest_tmp=$EVIDENCE_ROOT/$connector/.latest-run-id.tmp-$$
umask 077
printf '%s\n' "$NO_CRS_RUN_ID" > "$latest_tmp"
mv -f "$latest_tmp" "$latest_file"
if [ "$stage_rc" -eq 77 ]; then
    exit 77
fi
if [ "$stage_rc" -ne 0 ]; then
    exit "$stage_rc"
fi
exit 0
