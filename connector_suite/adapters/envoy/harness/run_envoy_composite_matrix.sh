#!/bin/sh
set -eu

# Real Envoy ext_authz+ext_proc composite matrix. Each case gets a fresh
# service process and event log. Output is verifier input, never a verdict.

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH= cd "$CONNECTOR_DIR/../.." && pwd)
HELPER="$SCRIPT_DIR/envoy_smoke_helper.py"
PROJECTION_WRITER="$SCRIPT_DIR/write_composite_verifier_projection.py"
TLS_RENDERER="$CONNECTOR_DIR/config/lib/tls_yaml_render.sh"
TEMPLATE="$CONNECTOR_DIR/config/envoy-ext-authz-composite.yaml.in"
VERSION_LOCK="$CONNECTOR_DIR/config/envoy-ext-proc-versions.env"
PYTHON_BIN=${PYTHON_BIN:-}

MATRIX_INPUT="${RUNTIME_ROOT:-}/composite-matrix-input.json"
TLS_CERTIFICATE="${RUNTIME_ROOT:-}/loopback.crt"
TLS_PRIVATE_KEY="${RUNTIME_ROOT:-}/loopback.key"
VERSION_OUTPUT="${RUNTIME_ROOT:-}/envoy-version.txt"
STOP_ATTEMPTS=${ENVOY_COMPOSITE_STOP_ATTEMPTS:-20}
STOP_DELAY_SECONDS=${ENVOY_COMPOSITE_STOP_DELAY_SECONDS:-0.1}
ENVOY_LOG_LEVEL=${ENVOY_COMPOSITE_LOG_LEVEL:-error}
P3_REDIRECT_TARGET=/msconnector-p3-redirect-target
envoy_pid=
service_pid=
upstream_pid=
envoy_start_token=
service_start_token=
upstream_start_token=

fail() { echo "envoy_composite_matrix: FAIL - $1" >&2; exit 1; }
blocked() { echo "envoy_composite_matrix: BLOCKED - $1" >&2; exit 77; }

[ -n "${RUNTIME_ROOT:-}" ] || blocked "RUNTIME_ROOT must be explicit"
[ -n "${ENVOY_BIN:-}" ] || blocked "ENVOY_BIN must be explicit"
[ -n "${COMPOSITE_BIN:-}" ] || blocked "COMPOSITE_BIN must be explicit"
[ -n "${COMPOSITE_RUNTIME_CONFIG:-}" ] || blocked "COMPOSITE_RUNTIME_CONFIG must be explicit"
[ -n "${EVENT_LOG_PATH:-}" ] || blocked "EVENT_LOG_PATH must be explicit and contain %CASE%"
[ -n "$PYTHON_BIN" ] || blocked "PYTHON_BIN must be explicit"
case "$ENVOY_LOG_LEVEL" in trace|debug|info|warning|warn|error|critical|off) ;; *) blocked "ENVOY_COMPOSITE_LOG_LEVEL is invalid" ;; esac

require_absolute() {
    absolute_path=$1; absolute_label=${2-}
    case "$absolute_path" in /*) ;; *) fail "$absolute_label must be absolute" ;; esac
}
require_file() {
    required_file_path=$1; required_file_label=${2-}
    [ -f "$required_file_path" ] || fail "$required_file_label is missing: $required_file_path"
    [ ! -L "$required_file_path" ] || fail "$required_file_label must not be a symlink: $required_file_path"
}
require_owner_controlled_input() {
    owner_input_path=$1
    "$PYTHON_BIN" - "$owner_input_path" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
try:
    current = path
    while True:
        info = current.lstat()
        if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise SystemExit(f"unsafe owner or mode: {current}")
        if current == current.parent:
            break
        current = current.parent
except OSError as exc:
    raise SystemExit(str(exc))
PY
}
require_executable() {
    required_executable_path=$1; required_executable_label=$2
    require_file "$required_executable_path" "$required_executable_label"
    [ -x "$required_executable_path" ] || fail "$required_executable_label is not executable: $required_executable_path"
}
require_trusted_path() {
    trusted_path=$1; trusted_path_role=$2
    "$PYTHON_BIN" - "$trusted_path" "$trusted_path_role" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
role = sys.argv[2]
uid = os.getuid()
if not path.is_absolute():
    raise SystemExit("path is not absolute")
current = path
while True:
    info = current.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"symlink in trusted path: {current}")
    is_leaf = current == path
    if is_leaf and role == "input" and info.st_uid != uid:
        raise SystemExit(f"input is not current-user-owned: {current}")
    if is_leaf and role == "binary" and info.st_uid not in (0, uid):
        raise SystemExit(f"binary has untrusted owner: {current}")
    if info.st_mode & 0o022:
        sticky_tmp = current == pathlib.Path("/var/tmp") and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if not sticky_tmp:
            raise SystemExit(f"group/world-writable trusted path: {current}")
    if not is_leaf and info.st_uid not in (0, uid):
        raise SystemExit(f"ancestor has untrusted owner: {current}")
    if current == current.parent:
        break
    current = current.parent
PY
}
require_runtime_parent_chain() {
    runtime_parent_path=$1
    "$PYTHON_BIN" - "$runtime_parent_path" <<'PY'
import os, pathlib, stat, sys
target = pathlib.Path(sys.argv[1])
uid = os.getuid()
if not target.is_absolute():
    raise SystemExit("runtime root is not absolute")
current = target
while not current.exists() and not current.is_symlink():
    if current == current.parent:
        break
    current = current.parent
while True:
    info = current.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"symlink in runtime path: {current}")
    if info.st_mode & 0o022:
        sticky_tmp = current == pathlib.Path("/var/tmp") and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if not sticky_tmp:
            raise SystemExit(f"unsafe runtime ancestor: {current}")
    if info.st_uid not in (0, uid):
        raise SystemExit(f"untrusted runtime ancestor owner: {current}")
    if current == current.parent:
        break
    current = current.parent
PY
}
within_runtime() {
    runtime_artifact_path=$1
    "$PYTHON_BIN" - "$RUNTIME_ROOT" "$runtime_artifact_path" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
target = pathlib.Path(sys.argv[2])
if not target.is_absolute():
    raise SystemExit("runtime artifact is not absolute")
try:
    target.resolve(strict=False).relative_to(root)
except ValueError:
    raise SystemExit("runtime artifact escapes RUNTIME_ROOT")
PY
}

start_token() {
    start_token_pid=$1
    "$PYTHON_BIN" - "$start_token_pid" <<'PY'
import pathlib, sys
pid = sys.argv[1]
if not pid.isdecimal():
    raise SystemExit(1)
try:
    line = pathlib.Path("/proc", pid, "stat").read_text(encoding="ascii")
except (OSError, UnicodeError):
    raise SystemExit(1)
close = line.rfind(")")
fields = line[close + 1:].split() if close >= 0 else []
if len(fields) < 20 or not fields[19].isdecimal():
    raise SystemExit(1)
print(fields[19])
PY
}
is_current() {
    current_pid=$1; current_token=$2
    [ -n "$current_token" ] || return 1
    [ "$(start_token "$current_pid" 2>/dev/null)" = "$current_token" ] || return 1
    [ "$(pid_uid "$current_pid" 2>/dev/null)" = "$(id -u)" ]
}
pid_uid() {
    pid_uid_pid=$1
    "$PYTHON_BIN" - "$pid_uid_pid" <<'PY'
import pathlib, sys
for line in pathlib.Path("/proc", sys.argv[1], "status").read_text(encoding="ascii").splitlines():
    if line.startswith("Uid:"):
        value = line.split()[1]
        if value.isdecimal():
            print(value)
            raise SystemExit(0)
raise SystemExit(1)
PY
}
is_zombie() {
    zombie_pid=$1
    "$PYTHON_BIN" - "$zombie_pid" <<'PY'
import pathlib, sys
try:
    line = pathlib.Path("/proc", sys.argv[1], "stat").read_text(encoding="ascii")
except (OSError, UnicodeError):
    raise SystemExit(1)
close = line.rfind(")")
fields = line[close + 1:].split() if close >= 0 else []
raise SystemExit(0 if fields and fields[0] == "Z" else 1)
PY
}
stop_owned() {
    pid=$1; token=$2; label=$3
    [ -n "$pid" ] || return 0
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid" 2>/dev/null || true; return 0; fi
    is_current "$pid" "$token" || { echo "envoy_composite_matrix: refusing unverified $label PID $pid" >&2; return 1; }
    kill -TERM "$pid" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt "$STOP_ATTEMPTS" ]; do
        if ! kill -0 "$pid" 2>/dev/null || is_zombie "$pid"; then wait "$pid" 2>/dev/null || true; return 0; fi
        # Ownership was verified immediately before TERM.  If the process
        # disappears between the liveness poll and this identity probe, never
        # signal a potentially reused PID; best-effort wait only for the
        # child we originally started and treat the task process as stopped.
        if ! is_current "$pid" "$token"; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        attempt=$((attempt + 1)); sleep "$STOP_DELAY_SECONDS"
    done
        # As above, a post-signal identity loss is completion, not authority
        # to send another signal to a possibly reused PID.
        if ! is_current "$pid" "$token"; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
    kill -KILL "$pid" 2>/dev/null || true
    attempt=0
    while [ "$attempt" -lt "$STOP_ATTEMPTS" ]; do
        if ! kill -0 "$pid" 2>/dev/null || is_zombie "$pid"; then wait "$pid" 2>/dev/null || true; return 0; fi
        attempt=$((attempt + 1)); sleep "$STOP_DELAY_SECONDS"
    done
    echo "envoy_composite_matrix: $label did not stop within bounded timeout" >&2
    return 1
}
cleanup() {
    rc=0
    stop_owned "$envoy_pid" "$envoy_start_token" envoy || rc=1
    stop_owned "$service_pid" "$service_start_token" composite || rc=1
    stop_owned "$upstream_pid" "$upstream_start_token" upstream || rc=1
    envoy_pid=; service_pid=; upstream_pid=
    return "$rc"
}
trap 'cleanup || exit 1' EXIT HUP INT TERM

require_absolute "$RUNTIME_ROOT" RUNTIME_ROOT
require_absolute "$ENVOY_BIN" ENVOY_BIN
require_absolute "$COMPOSITE_BIN" COMPOSITE_BIN
require_absolute "$COMPOSITE_RUNTIME_CONFIG" COMPOSITE_RUNTIME_CONFIG
require_absolute "$EVENT_LOG_PATH" EVENT_LOG_PATH
require_absolute "$PYTHON_BIN" PYTHON_BIN
case "$EVENT_LOG_PATH" in *%CASE%*) ;; *) fail "EVENT_LOG_PATH must contain literal %CASE%" ;; esac
case "$RUNTIME_ROOT" in "$REPO_ROOT"|"$REPO_ROOT"/*) fail "RUNTIME_ROOT is inside checkout" ;; *) : ;; esac
require_executable "$ENVOY_BIN" Envoy
require_executable "$COMPOSITE_BIN" composite
require_file "$COMPOSITE_RUNTIME_CONFIG" composite_runtime_config
require_executable "$PYTHON_BIN" Python
require_trusted_path "$PYTHON_BIN" binary || blocked "Python path is not trusted: $PYTHON_BIN"
require_trusted_path "$ENVOY_BIN" binary || fail "Envoy path chain is not trusted"
require_trusted_path "$COMPOSITE_BIN" binary || fail "composite path chain is not trusted"
require_trusted_path "$COMPOSITE_RUNTIME_CONFIG" input || fail "runtime config is not owner-controlled"
require_file "$TEMPLATE" composite_template
require_file "$VERSION_LOCK" Envoy_version_lock
require_file "$PROJECTION_WRITER" Envoy_verifier_projection_writer
require_trusted_path "$TEMPLATE" input || fail "composite template path chain is not owner-controlled"
require_trusted_path "$VERSION_LOCK" input || fail "version lock path chain is not owner-controlled"
require_trusted_path "$PROJECTION_WRITER" input || fail "verifier projection writer path chain is not owner-controlled"
command -v openssl >/dev/null 2>&1 || blocked "openssl is required"

ensure_directory() {
    ensured_directory=$1
    "$PYTHON_BIN" - "$ensured_directory" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
if path.exists() or path.is_symlink():
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SystemExit("runtime directory is not a real directory")
else:
    path.mkdir(mode=0o700)
info = path.lstat()
if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
    raise SystemExit("runtime directory is not owner-only")
PY
}
require_runtime_parent_chain "$RUNTIME_ROOT" || blocked "RUNTIME_ROOT path chain is not trusted"
ensure_directory "$RUNTIME_ROOT" || fail "unsafe RUNTIME_ROOT"
"$PYTHON_BIN" "$HELPER" prepare-runtime-root --runtime-root "$RUNTIME_ROOT" || fail "unsafe RUNTIME_ROOT"
"$PYTHON_BIN" - "$RUNTIME_ROOT" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
info = root.lstat()
if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit("runtime root is not a real directory")
if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
    raise SystemExit("runtime root is not current-user owner-only")
if any(root.iterdir()):
    raise SystemExit("runtime root is not fresh and empty")
PY
ensure_directory "$RUNTIME_ROOT/cases" || fail "unsafe cases directory"
within_runtime "$MATRIX_INPUT"; within_runtime "$TLS_CERTIFICATE"; within_runtime "$TLS_PRIVATE_KEY"; within_runtime "$VERSION_OUTPUT"
event_log_parent=$(dirname "$EVENT_LOG_PATH")
within_runtime "$event_log_parent"
require_trusted_path "$event_log_parent" input || fail "event-log parent path chain is not owner-controlled"
pinned_envoy_release=$(sed -n 's/^ENVOY_RELEASE=//p' "$VERSION_LOCK")
[ -n "$pinned_envoy_release" ] || fail "version lock has no ENVOY_RELEASE"
"$ENVOY_BIN" --version >"$VERSION_OUTPUT" 2>&1 || fail "could not read Envoy version"
chmod 600 "$VERSION_OUTPUT" || fail "could not restrict Envoy version artifact"
envoy_version=$(sed -n '/[^[:space:]]/ { p; q; }' "$VERSION_OUTPUT")
case "$envoy_version" in *"/$pinned_envoy_release/"*|*"version: $pinned_envoy_release"*) ;; *) fail "Envoy does not match pinned $pinned_envoy_release" ;; esac
. "$TLS_RENDERER"
create_private_loopback_tls "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY" || fail "could not create private TLS"

write_case_record() {
    record_path=$1; record_case_id=$2; record_phase=$3; record_status=$4
    record_event_log=$5; record_probe=$6; record_structural=$7
    record_binding=${8:-one_fresh_service_and_event_log_per_case}; record_upstream=${9:-}
    record_config=${10:-}; record_client_probe=${11:-}; record_upstream_state=${12:-not_reached}
    record_verifier_manifest=${13:-}; record_verifier_summary=${14:-}; record_verifier_status=${15:-not_run}
    "$PYTHON_BIN" - "$record_path" "$record_case_id" "$record_phase" "$record_status" \
        "$record_event_log" "$record_probe" "$record_structural" "$record_binding" \
        "$record_upstream" "$ENVOY_BIN" "$COMPOSITE_BIN" "$record_config" \
        "$record_client_probe" "$record_upstream_state" "$record_verifier_manifest" \
        "$record_verifier_summary" "$record_verifier_status" "$RUNTIME_ROOT" <<'PY'
import hashlib, json, os, pathlib, stat, sys
path, case_id, phase, status, event_log, probe, structural, binding, upstream_observation, envoy_binary, composite_binary, config, client_probe, upstream_state, verifier_manifest, verifier_summary, verifier_status, runtime_root_text = sys.argv[1:]
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_PRIVATE_BYTES = 16 * 1024 * 1024
runtime_root = pathlib.Path(runtime_root_text).resolve(strict=True)

def artifact(path_text, label, private=False):
    if not path_text:
        return None
    path = pathlib.Path(path_text)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (private and (stat.S_IMODE(info.st_mode) & 0o77 or info.st_uid != os.getuid())):
        raise SystemExit(f"{label} is not an owner-only regular file")
    if private:
        try:
            path.resolve(strict=True).relative_to(runtime_root)
        except (OSError, ValueError):
            raise SystemExit(f"{label} escapes RUNTIME_ROOT")
        if info.st_nlink != 1:
            raise SystemExit(f"{label} must not be hard-linked")
    limit = MAX_PRIVATE_BYTES if private else MAX_BINARY_BYTES
    if info.st_size > limit:
        raise SystemExit(f"{label} exceeds bounded hash input")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "size_bytes": info.st_size}

envoy = artifact(envoy_binary, "Envoy binary")
composite = artifact(composite_binary, "composite binary")
event_artifact = artifact(event_log, "event JSONL", private=True)
structural_artifact = artifact(structural, "structural event artifact", private=True)
config_artifact = artifact(config, "rendered config", private=True)
probe_artifact = artifact(client_probe or probe, "client probe", private=True)
upstream_artifact = artifact(upstream_observation, "upstream observation", private=True)
verifier_manifest_artifact = artifact(verifier_manifest, "shared verifier manifest", private=True)
verifier_summary_artifact = artifact(verifier_summary, "shared verifier summary", private=True)
record = {
    "schema_version": 1, "connector": "envoy",
    "integration": "ext_authz_ext_proc_composite", "case_id": case_id,
    "phase": phase, "observed_http_status": None if status == "not_run" else int(status),
    "event_log": event_log, "probe_artifact": probe,
    "structural_event_artifact": structural,
    "event_log_artifact": event_artifact,
    "structural_event_artifact_binding": structural_artifact,
    "upstream_observation_artifact": upstream_observation,
    "started_binary_artifacts": {"envoy": envoy, "composite": composite},
    "rendered_config_artifact": config_artifact,
    "client_observation_artifact": probe_artifact,
    "upstream_observation": upstream_artifact,
    "causal_binding": "started_binary_config_client_upstream_artifacts" if upstream_artifact else "started_binary_config_client_no_upstream_request_observed",
    "upstream_observation_state": upstream_state,
    "client_protocol": "HTTP/1.1",
    "host_execution_evidence": "real_envoy_http1_client_observation" if status != "not_run" else "not_run",
    "decision_id_binding": binding,
    "shared_verifier_manifest_artifact": verifier_manifest_artifact,
    "shared_verifier_summary_artifact": verifier_summary_artifact,
    "shared_verifier_status": verifier_status,
    "verdict": "lifecycle_only_not_catalog_acceptance" if verifier_status == "LIFECYCLE_ONLY" else "deferred_to_shared_verifier",
    "host_execution_status": "structural_input_only",
    "payloads_persisted": False,
}
pathlib.Path(path).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY
}

check_event_log() {
    checked_event_path=$1; checked_event_output=$2; checked_event_case_id=$3
    "$PYTHON_BIN" - "$checked_event_path" "$checked_event_output" "$checked_event_case_id" <<'PY'
import json, os, pathlib, stat, sys
event_path, output_path, case_id = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
MAX_EVENT_LOG_BYTES = 256 * 1024
MAX_EVENT_LINE_BYTES = 16 * 1024
no_follow = getattr(os, "O_NOFOLLOW", 0)
if not no_follow:
    raise SystemExit("event log validation requires O_NOFOLLOW")
descriptor = os.open(event_path, os.O_RDONLY | no_follow)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
    ):
        raise SystemExit("event log is not an owner-private regular file")
    if before.st_size > MAX_EVENT_LOG_BYTES:
        raise SystemExit("event log exceeds bounded verifier input")
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_EVENT_LOG_BYTES:
            raise SystemExit("event log exceeds bounded verifier input")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_nlink) != (
        after.st_dev, after.st_ino, after.st_size, after.st_nlink,
    ):
        raise SystemExit("event log changed while being validated")
finally:
    os.close(descriptor)
try:
    raw_records = b"".join(chunks).decode("utf-8").splitlines(keepends=True)
except UnicodeDecodeError as exc:
    raise SystemExit("event log is not UTF-8 metadata") from exc
allowed = {
    "decision_id", "connector", "rule_id", "phase", "outcome", "reason",
    "requested_action", "actual_host_action", "visible_status", "cleanup_outcome",
    "event_time", "request_path", "response_path", "transport",
}
required = {"decision_id", "connector", "phase", "outcome", "event_time", "request_path", "response_path", "transport"}
forbidden = ("body", "lease", "credential", "secret", "token", "password", "headers", "uri", "client_ip", "request_id", "transaction_id")
pipeline = ("envoy.ext_authz", "envoy.ext_proc", "envoy_ext_authz_ext_proc_grpc")
expected_rules = {
    "p1_deny": ("P1", "1101001"),
    "p2_deny": ("P2", "1102001"),
    "p3_deny": ("P3", "1103001"),
    "p3_redirect": ("P3", "1103002"),
    "p4_safe": ("P4", "1104002"),
    "follow_up_p1_deny": ("P1", "1101001"),
}
records = []
for number, line in enumerate(raw_records, 1):
    if len(line.encode("utf-8")) > MAX_EVENT_LINE_BYTES:
        raise SystemExit(f"event {number} exceeds bounded verifier input")
    if not line.strip():
        raise SystemExit(f"event {number} is blank")
    value = json.loads(line)
    if not isinstance(value, dict) or set(value) - allowed:
        raise SystemExit(f"event {number} contains unsupported or payload fields")
    if any(word in key.lower() for key in value for word in forbidden):
        raise SystemExit(f"event {number} contains forbidden caller or payload metadata")
    if not required.issubset(value):
        raise SystemExit(f"event {number} is missing bounded pipeline metadata")
    if not isinstance(value.get("decision_id"), str) or not 16 <= len(value["decision_id"]) <= 256:
        raise SystemExit("missing server-generated decision_id")
    if value.get("connector") != "envoy" or (value["request_path"], value["response_path"], value["transport"]) != pipeline:
        raise SystemExit(f"event {number} does not bind to the Envoy composite pipeline")
    if "rule_id" in value and (not isinstance(value["rule_id"], str) or not value["rule_id"].isdigit() or len(value["rule_id"]) > 128):
        raise SystemExit(f"event {number} has an invalid bounded rule identifier")
    records.append(value)
decision_ids = {value["decision_id"] for value in records}
if len(decision_ids) != 1:
    raise SystemExit(f"expected one unique decision_id, found {len(decision_ids)}")
if case_id == "companion_unavailable":
    terminal = [value for value in records if value.get("phase") == "terminal"]
    if (len(terminal) != 1 or terminal[0].get("reason") != "restart"
            or terminal[0].get("outcome") != "closed"
            or terminal[0].get("cleanup_outcome") != "closed"):
        raise SystemExit("companion shutdown requires one successful native restart cleanup")
if case_id in expected_rules:
    phase, rule_id = expected_rules[case_id]
    matched = [value for value in records if value.get("phase") == phase]
    if len(matched) != 1 or matched[0].get("rule_id") != rule_id:
        raise SystemExit(f"{case_id} did not retain expected {phase} rule_id={rule_id}")
pathlib.Path(output_path).write_text(json.dumps({
    "schema_version": 1, "event_count": len(records),
    "unique_decision_id_count": len(decision_ids),
    "payloads_persisted": False, "pipeline_metadata_verified": True,
    "selected_rule_id_verified": case_id in expected_rules,
    "verdict": "structural_input_only",
}, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(output_path, 0o600)
PY
}

check_client_probe() {
    checked_client_probe=$1
    "$PYTHON_BIN" - "$checked_client_probe" <<'PY'
import json, os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
info = path.lstat()
if (
    not stat.S_ISREG(info.st_mode)
    or stat.S_IMODE(info.st_mode) != 0o600
    or info.st_uid != os.getuid()
    or info.st_nlink != 1
    or info.st_size > 16 * 1024
):
    raise SystemExit("client probe is not bounded owner-private metadata")
value = json.loads(path.read_text(encoding="utf-8"))
allowed = {
    "schema_version", "evidence_type", "http_status", "response_bytes",
    "body_payload_persisted", "redirect_location_verified", "composite_lease_header_present",
}
if set(value) - allowed or not {"schema_version", "evidence_type", "http_status", "body_payload_persisted", "redirect_location_verified", "composite_lease_header_present"}.issubset(value):
    raise SystemExit("client probe has an unexpected metadata schema")
if value.get("schema_version") != 1 or value.get("evidence_type") != "envoy_http_client_probe":
    raise SystemExit("client probe has an unexpected identity")
if type(value.get("http_status")) is not int or not 100 <= value["http_status"] <= 599:
    raise SystemExit("client probe has an invalid HTTP status")
if value.get("body_payload_persisted") is not False:
    raise SystemExit("client probe retained a response payload")
if type(value.get("redirect_location_verified")) is not bool:
    raise SystemExit("client probe has an invalid redirect Location attestation")
if value.get("composite_lease_header_present") is not False:
    raise SystemExit("client observed a private composite lease header")
if "response_bytes" in value and (type(value["response_bytes"]) is not int or value["response_bytes"] < 0):
    raise SystemExit("client probe has an invalid response byte count")
PY
}

verifier_case_supported() {
    verifier_case_id=$1
    case "$verifier_case_id" in
        p1_allow|p1_deny|p2_allow|p2_deny|p2_oversize|p3_deny|p3_redirect|p4_safe|envoy_response_metadata_omitted) return 0 ;;
        *) return 1 ;;
    esac
}

wait_for_event_phase() {
    event_path=$1; expected_phase=$2; expected_reason=${3:-}
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if "$PYTHON_BIN" - "$event_path" "$expected_phase" "$expected_reason" <<'PY' >/dev/null 2>&1
import json, os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
phase, reason = sys.argv[2:]
maximum_bytes = 256 * 1024
maximum_line_bytes = 16 * 1024
no_follow = getattr(os, "O_NOFOLLOW", 0)
if not no_follow or path.is_symlink():
    raise SystemExit(1)
try:
    descriptor = os.open(path, os.O_RDONLY | no_follow)
except OSError:
    raise SystemExit(1)
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > maximum_bytes:
        raise SystemExit(1)
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, 64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise SystemExit(1)
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if (info.st_dev, info.st_ino, info.st_size, info.st_nlink) != (after.st_dev, after.st_ino, after.st_size, after.st_nlink):
        raise SystemExit(1)
finally:
    os.close(descriptor)
for raw_line in b"".join(chunks).splitlines(keepends=True):
    if len(raw_line) > maximum_line_bytes:
        raise SystemExit(1)
    try:
        event = json.loads(raw_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit(1)
    if event.get("phase") == phase and (not reason or event.get("reason") == reason):
        raise SystemExit(0)
raise SystemExit(1)
PY
        then return 0; fi
        attempt=$((attempt + 1)); sleep 0.1
    done
    return 1
}

probe_with_timeout() {
    timeout_probe_port=$1; timeout_probe_certificate=$2; timeout_probe_path=$3
    timeout_probe_method=$4; timeout_probe_body=$5; timeout_probe_evidence=$6
    "$PYTHON_BIN" - "$timeout_probe_port" "$timeout_probe_certificate" "$timeout_probe_path" \
        "$timeout_probe_method" "$timeout_probe_body" "$timeout_probe_evidence" <<'PY'
import json, pathlib, socket, ssl, sys
port, cert, path, method, body, evidence = sys.argv[1:]
timeout = 10.0
payload = body.encode("utf-8")
request = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", "Connection: close"]
if payload:
    request.append(f"Content-Length: {len(payload)}")
request_bytes = ("\r\n".join(request) + "\r\n\r\n").encode() + payload
context = ssl.create_default_context(cafile=cert)
with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as raw:
    with context.wrap_socket(raw, server_hostname="127.0.0.1") as conn:
        conn.settimeout(timeout)
        conn.sendall(request_bytes)
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 16384:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
status_line = bytes(data).split(b"\r\n", 1)[0].decode("ascii", "replace")
status = int(status_line.split()[1]) if len(status_line.split()) >= 2 else 0
header_block = bytes(data).split(b"\r\n\r\n", 1)[0]
composite_lease_header_present = any(
    line.lower().startswith(b"x-msconnector-composite-lease:")
    for line in header_block.split(b"\r\n")[1:]
)
pathlib.Path(evidence).write_text(json.dumps({
    "schema_version": 1, "evidence_type": "envoy_http_client_probe",
    "http_status": status, "body_payload_persisted": False,
    "redirect_location_verified": False,
    "composite_lease_header_present": composite_lease_header_present,
}, sort_keys=True) + "\n", encoding="utf-8")
pathlib.Path(evidence).chmod(0o600)
print(status)
PY
}

render_config() {
    render_output=$1; render_listen_port=$2; render_upstream_port=$3
    render_authz_port=$4; render_admin_port=$5
    render_metadata_namespace=${6:-envoy.filters.http.ext_authz}
    cert=$(render_yaml_path_for_sed_replacement "$TLS_CERTIFICATE") || fail "unsafe certificate path"
    key=$(render_yaml_path_for_sed_replacement "$TLS_PRIVATE_KEY") || fail "unsafe key path"
    sed -e "s|@LISTEN_PORT@|$render_listen_port|g" -e "s|@UPSTREAM_PORT@|$render_upstream_port|g" \
        -e "s|@AUTHZ_PORT@|$render_authz_port|g" -e "s|@ADMIN_PORT@|$render_admin_port|g" \
        -e "s|@EXT_PROC_METADATA_NAMESPACE@|$render_metadata_namespace|g" \
        -e "s|@TLS_CERTIFICATE@|$cert|g" -e "s|@TLS_PRIVATE_KEY@|$key|g" \
        "$TEMPLATE" >"$render_output"
    chmod 600 "$render_output"
}

wait_for_listener() {
    listener_port=$1
    attempt=0
    while [ "$attempt" -lt 40 ]; do
        kill -0 "$service_pid" 2>/dev/null && kill -0 "$envoy_pid" 2>/dev/null || return 1
        if "$PYTHON_BIN" - "$listener_port" <<'PY' >/dev/null 2>&1
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2): pass
PY
        then return 0; fi
        attempt=$((attempt + 1)); sleep 0.1
    done
    return 1
}

wait_for_composite_listener() {
    composite_listener_port=$1
    attempt=0
    while [ "$attempt" -lt 40 ]; do
        kill -0 "$service_pid" 2>/dev/null || return 1
        if "$PYTHON_BIN" - "$composite_listener_port" <<'PY' >/dev/null 2>&1
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2): pass
PY
        then return 0; fi
        attempt=$((attempt + 1)); sleep 0.1
    done
    return 1
}

start_catalog_upstream() {
    catalog_port=$1; catalog_stdout=$2; catalog_stderr=$3
    catalog_response_delay=${4:-0}; catalog_request_observation=${5:-}; catalog_response_observation=${6:-}
    (
        exec "$PYTHON_BIN" - "$catalog_port" "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY" \
            "$catalog_response_delay" "$catalog_request_observation" "$catalog_response_observation" "$RUNTIME_ROOT" <<'PY'
import http.server, json, os, pathlib, ssl, stat, sys
import time

port, certificate, private_key, response_delay, request_observation_path, response_observation_path, runtime_root_text = int(sys.argv[1]), sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5], sys.argv[6], sys.argv[7]
runtime_root = pathlib.Path(runtime_root_text).resolve(strict=True)

def write_observation(observation_path, request_observed, response_observed, lease_header_present):
    if not observation_path:
        return
    path = pathlib.Path(observation_path)
    if path.is_symlink() or not path.is_absolute():
        raise RuntimeError("unsafe upstream observation path")
    try:
        path.resolve(strict=False).relative_to(runtime_root)
    except ValueError as exc:
        raise RuntimeError("upstream observation escapes runtime root") from exc
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not no_follow:
        raise RuntimeError("upstream observation requires O_NOFOLLOW")
    payload = json.dumps({
        "request_observed": request_observed,
        "response_observed": response_observed,
        "composite_lease_header_present": lease_header_present,
    }, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise RuntimeError("upstream observation is not a private regular file")
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args):
        del fmt, args
    def do_GET(self):
        self.respond()
    def do_POST(self):
        length = int(self.headers.get("content-length", "0") or "0")
        if length > 0:
            self.rfile.read(min(length, 65536))
        self.respond()
    def respond(self):
        write_observation(
            request_observation_path,
            True,
            False,
            "x-msconnector-composite-lease" in self.headers,
        )
        if response_delay:
            time.sleep(response_delay)
        headers = []
        bodies = {
            "/vector/allow": b"allow-control-response",
            "/vector/p2-empty": b"empty-body-response",
            "/vector/p3": b"p3-response-body-without-p4-marker",
            "/vector/p3-redirect": b"p3-redirect-upstream-response",
            "/vector/p4": b"p4-response-msconnector-p4-only",
            "/vector/p4-safe": b"p4-safe-response-msconnector-p4-safe",
            "/vector/p4-strict": b"p4-strict-response-msconnector-p4-strict",
        }
        if self.path == "/vector/p3":
            headers.append(("X-Msconnector-Vector", "msconnector-p3-only"))
        elif self.path == "/vector/p3-redirect":
            headers.append(("X-Msconnector-Vector", "msconnector-p3-redirect"))
        body = bodies.get(self.path, b"catalog-upstream-unrecognized-path")
        self.send_response(200)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        write_observation(
            response_observation_path,
            True,
            True,
            "x-msconnector-composite-lease" in self.headers,
        )

server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, private_key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
    ) >"$catalog_stdout" 2>"$catalog_stderr" &
    upstream_pid=$!
    upstream_start_token=$(start_token "$upstream_pid") || fail "catalog upstream ownership unavailable"
}

run_case() {
    case_id=$1; phase=$2; method=$3; request_path=$4; request_header=$5; request_body=$6
    upstream_delay=${7:-0}; probe_timeout=${8:-2}; metadata_namespace=${9:-envoy.filters.http.ext_authz}; kill_companion=${10:-0}
    case_dir="$RUNTIME_ROOT/cases/$case_id"; ensure_directory "$case_dir" || fail "unsafe case directory: $case_id"
    case_event_log=$(printf '%s' "$EVENT_LOG_PATH" | sed "s/%CASE%/$case_id/g")
    within_runtime "$case_event_log"
    case_probe="$case_dir/probe.json"; case_structural="$case_dir/structural-events.json"
    case_upstream_request_observation="$case_dir/upstream-request-observation.json"
    case_upstream_response_observation="$case_dir/upstream-response-observation.json"
    case_config="$case_dir/envoy.yaml"; case_record="$case_dir/case-input.json"
    case_verifier_events="$case_dir/verifier-events.jsonl"
    case_verifier_client="$case_dir/verifier-client.observation.json"
    case_verifier_upstream="$case_dir/verifier-upstream.observation.json"
    case_verifier_manifest="$case_dir/verifier-manifest.json"
    case_verifier_summary="$case_dir/verifier-summary.json"
    for artifact in "$case_event_log" "$case_probe" "$case_structural" "$case_upstream_request_observation" "$case_upstream_response_observation" "$case_record" "$case_config" "$case_verifier_events" "$case_verifier_client" "$case_verifier_upstream" "$case_verifier_manifest" "$case_verifier_summary"; do
        within_runtime "$artifact"; [ ! -L "$artifact" ] || fail "symlink artifact: $artifact"; rm -f "$artifact"
    done
    set -- $("$PYTHON_BIN" "$HELPER" free-ports --count 4)
    [ "$#" -eq 4 ] || fail "case port allocator returned unexpected output"
    case_listen_port=$1; case_upstream_port=$2; case_authz_port=$3; case_admin_port=$4
    render_config "$case_config" "$case_listen_port" "$case_upstream_port" "$case_authz_port" "$case_admin_port" "$metadata_namespace"
    "$ENVOY_BIN" --mode validate -c "$case_config" --base-id "$((case_listen_port + case_admin_port))" --disable-hot-restart \
        >"$case_dir/envoy-validate.stdout.log" 2>"$case_dir/envoy-validate.stderr.log" ||
        fail "Envoy rejected config for case $case_id"
    start_catalog_upstream "$case_upstream_port" "$case_dir/upstream.stdout.log" "$case_dir/upstream.stderr.log" "$upstream_delay" "$case_upstream_request_observation" "$case_upstream_response_observation"
    "$COMPOSITE_BIN" --mode envoy --listen "127.0.0.1:$case_authz_port" --runtime-config "$COMPOSITE_RUNTIME_CONFIG" \
        --event-log "$case_event_log" >"$case_dir/composite.stdout.log" 2>"$case_dir/composite.stderr.log" &
    service_pid=$!; service_start_token=$(start_token "$service_pid") || fail "composite ownership unavailable"
    wait_for_composite_listener "$case_authz_port" || fail "composite listener was not ready for case $case_id"
    "$ENVOY_BIN" -c "$case_config" --base-id "$((case_listen_port + case_admin_port))" --disable-hot-restart --log-level "$ENVOY_LOG_LEVEL" \
        >"$case_dir/envoy.stdout.log" 2>"$case_dir/envoy.stderr.log" &
    envoy_pid=$!; envoy_start_token=$(start_token "$envoy_pid") || fail "Envoy ownership unavailable"
    wait_for_listener "$case_listen_port" || fail "Envoy listener was not ready for case $case_id"
    set +e
    if [ "$kill_companion" -eq 1 ]; then
        "$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
            --url "https://127.0.0.1:$case_listen_port$request_path" --method "$method" --no-redirect \
            --evidence-path "$case_probe" >"$case_dir/probe.status" 2>"$case_dir/probe.stderr.log" &
        probe_pid=$!
        wait_for_event_phase "$case_event_log" lease || fail "lease was not observed before companion stop for $case_id"
        stop_owned "$service_pid" "$service_start_token" composite || fail "companion stop failed for $case_id"
        service_pid=; service_start_token=
        wait "$probe_pid"; probe_rc=$?
        observed_status=$(sed -n '1p' "$case_dir/probe.status")
    elif [ "$probe_timeout" -gt 2 ]; then
        observed_status=$(probe_with_timeout "$case_listen_port" "$TLS_CERTIFICATE" "$request_path" "$method" "$request_body" "$case_probe")
        probe_rc=$?
    elif [ -n "$request_header" ] && [ -n "$request_body" ]; then
        observed_status=$("$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
            --url "https://127.0.0.1:$case_listen_port$request_path" --method "$method" --header "$request_header" \
            --data "$request_body" --no-redirect --evidence-path "$case_probe")
        probe_rc=$?
    elif [ -n "$request_header" ]; then
        observed_status=$("$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
            --url "https://127.0.0.1:$case_listen_port$request_path" --method "$method" --header "$request_header" \
            --no-redirect --evidence-path "$case_probe")
        probe_rc=$?
    elif [ -n "$request_body" ]; then
        observed_status=$("$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
            --url "https://127.0.0.1:$case_listen_port$request_path" --method "$method" --data "$request_body" \
            --no-redirect --evidence-path "$case_probe")
        probe_rc=$?
    elif [ "$case_id" = p3_redirect ]; then
        observed_status=$("$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
            --url "https://127.0.0.1:$case_listen_port$request_path" --method "$method" --no-redirect \
            --require-response-header "Location: $P3_REDIRECT_TARGET" --evidence-path "$case_probe")
        probe_rc=$?
    else
        observed_status=$("$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
            --url "https://127.0.0.1:$case_listen_port$request_path" --method "$method" --no-redirect \
            --evidence-path "$case_probe")
        probe_rc=$?
    fi
    set -e
    [ "$probe_rc" -eq 0 ] || fail "probe failed for case $case_id"
    case "$observed_status" in ''|*[!0-9]*) fail "non-status probe result for $case_id" ;; *) : ;; esac
    check_client_probe "$case_probe" || fail "client probe evidence failed for $case_id"
    if [ "$case_id" = p3_redirect ]; then
        [ "$observed_status" = 302 ] || fail "P3 redirect status was not 302"
    fi
    if [ "$case_id" = companion_unavailable ]; then
        [ "$observed_status" = 500 ] || fail "unavailable companion did not retain native Envoy error status"
    fi
    if [ "$case_id" = envoy_response_metadata_omitted ]; then
        [ "$observed_status" = 503 ] || fail "response metadata omission did not fail closed"
        wait_for_event_phase "$case_event_log" terminal timeout || fail "response metadata omission did not reach bounded timeout cleanup"
    fi
    if [ "$case_id" = spoofed_lease_header ]; then
        "$PYTHON_BIN" - "$case_upstream_response_observation" <<'PY'
import json, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
    raise SystemExit("upstream observation is not an owner-only regular file")
value = json.loads(path.read_text(encoding="ascii"))
if value != {
    "request_observed": True,
    "response_observed": True,
    "composite_lease_header_present": False,
}:
    raise SystemExit("client lease header reached upstream")
PY
        [ "$observed_status" = 200 ] || fail "spoofed lease header did not allow normally"
    fi
    upstream_artifact_path=
    upstream_observation_state=not_reached
    if [ -f "$case_upstream_request_observation" ]; then
        upstream_artifact_path=$case_upstream_request_observation
        upstream_observation_state=request_started
    fi
    if [ -f "$case_upstream_response_observation" ]; then
        upstream_artifact_path=$case_upstream_response_observation
        upstream_observation_state=response_observed
    fi
    cleanup || fail "bounded cleanup failed for case $case_id"
    check_event_log "$case_event_log" "$case_structural" "$case_id" || fail "event binding failed for $case_id"
    case_verifier_status=not_run
    case_verifier_manifest_artifact=
    case_verifier_summary_artifact=
    if verifier_case_supported "$case_id"; then
        "$PYTHON_BIN" "$PROJECTION_WRITER" \
            --runtime-root "$RUNTIME_ROOT" \
            --case-root "$case_dir" \
            --case "$case_id" \
            --event-log "$case_event_log" \
            --probe "$case_probe" \
            --upstream-request-observation "$case_upstream_request_observation" \
            --upstream-response-observation "$case_upstream_response_observation" \
            >/dev/null || fail "shared verifier projection failed for $case_id"
        case_verifier_status=LIFECYCLE_ONLY
        case_verifier_manifest_artifact=$case_verifier_manifest
        case_verifier_summary_artifact=$case_verifier_summary
    fi
    if [ "$case_id" = spoofed_lease_header ]; then
        write_case_record "$case_record" "$case_id" "$phase" "$observed_status" "$case_event_log" "$case_probe" "$case_structural" one_fresh_service_and_event_log_per_case "$upstream_artifact_path" "$case_config" "$case_probe" "$upstream_observation_state" "$case_verifier_manifest_artifact" "$case_verifier_summary_artifact" "$case_verifier_status"
    else
        write_case_record "$case_record" "$case_id" "$phase" "$observed_status" "$case_event_log" "$case_probe" "$case_structural" one_fresh_service_and_event_log_per_case "$upstream_artifact_path" "$case_config" "$case_probe" "$upstream_observation_state" "$case_verifier_manifest_artifact" "$case_verifier_summary_artifact" "$case_verifier_status"
    fi
    envoy_pid=; service_pid=; upstream_pid=; envoy_start_token=; service_start_token=; upstream_start_token=
}

run_follow_up_case() {
    case_id=follow_up_control
    case_dir="$RUNTIME_ROOT/cases/$case_id"; ensure_directory "$case_dir" || fail "unsafe case directory: $case_id"
    case_event_log=$(printf '%s' "$EVENT_LOG_PATH" | sed "s/%CASE%/$case_id/g")
    deny_probe="$case_dir/deny-probe.json"; allow_probe="$case_dir/allow-probe.json"
    deny_log="$case_dir/p1-deny.events.jsonl"; allow_log="$case_dir/p1-allow.events.jsonl"
    summary="$case_dir/follow-up-summary.json"; case_config="$case_dir/envoy.yaml"
    for artifact in "$case_event_log" "$deny_probe" "$allow_probe" "$deny_log" "$allow_log" "$summary" "$case_config"; do
        within_runtime "$artifact"; [ ! -L "$artifact" ] || fail "symlink artifact: $artifact"; rm -f "$artifact"
    done
    set -- $($PYTHON_BIN "$HELPER" free-ports --count 4)
    [ "$#" -eq 4 ] || fail "case port allocator returned unexpected output"
    case_listen_port=$1; case_upstream_port=$2; case_authz_port=$3; case_admin_port=$4
    render_config "$case_config" "$case_listen_port" "$case_upstream_port" "$case_authz_port" "$case_admin_port" envoy.filters.http.ext_authz
    "$ENVOY_BIN" --mode validate -c "$case_config" --base-id "$((case_listen_port + case_admin_port))" --disable-hot-restart \
        >"$case_dir/envoy-validate.stdout.log" 2>"$case_dir/envoy-validate.stderr.log" ||
        fail "Envoy rejected config for case $case_id"
    start_catalog_upstream "$case_upstream_port" "$case_dir/upstream.stdout.log" "$case_dir/upstream.stderr.log"
    "$COMPOSITE_BIN" --mode envoy --listen "127.0.0.1:$case_authz_port" --runtime-config "$COMPOSITE_RUNTIME_CONFIG" \
        --event-log "$case_event_log" >"$case_dir/composite.stdout.log" 2>"$case_dir/composite.stderr.log" &
    service_pid=$!; service_start_token=$(start_token "$service_pid") || fail "composite ownership unavailable"
    wait_for_composite_listener "$case_authz_port" || fail "composite listener was not ready for case $case_id"
    "$ENVOY_BIN" -c "$case_config" --base-id "$((case_listen_port + case_admin_port))" --disable-hot-restart --log-level "$ENVOY_LOG_LEVEL" \
        >"$case_dir/envoy.stdout.log" 2>"$case_dir/envoy.stderr.log" &
    envoy_pid=$!; envoy_start_token=$(start_token "$envoy_pid") || fail "Envoy ownership unavailable"
    wait_for_listener "$case_listen_port" || fail "Envoy listener was not ready for case $case_id"
    set +e
    deny_status=$("$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
        --url "https://127.0.0.1:$case_listen_port/vector/p1" --method GET --header "X-Msconnector-Vector: msconnector-p1-only" \
        --no-redirect --evidence-path "$deny_probe")
    deny_rc=$?
    set -e
    [ "$deny_rc" -eq 0 ] || fail "follow-up deny probe failed"
    [ "$deny_status" = 403 ] || fail "follow-up deny status was not 403: $deny_status"
    set +e
    allow_status=$("$PYTHON_BIN" "$HELPER" probe --runtime-root "$RUNTIME_ROOT" --tls-certificate "$TLS_CERTIFICATE" \
        --url "https://127.0.0.1:$case_listen_port/vector/allow" --method GET --no-redirect --evidence-path "$allow_probe")
    allow_rc=$?
    set -e
    [ "$allow_rc" -eq 0 ] || fail "follow-up allow probe failed"
    [ "$allow_status" = 200 ] || fail "follow-up allow status was not 200: $allow_status"
    cleanup || fail "bounded cleanup failed for case $case_id"
    "$PYTHON_BIN" - "$case_event_log" "$deny_log" "$allow_log" "$summary" <<'PY'
import json, os, pathlib, sys
source = pathlib.Path(sys.argv[1])
deny_path = pathlib.Path(sys.argv[2])
allow_path = pathlib.Path(sys.argv[3])
summary_path = pathlib.Path(sys.argv[4])
groups = {}
order = []
for line in source.read_text(encoding="utf-8").splitlines():
    if not line:
        continue
    value = json.loads(line)
    decision_id = value.get("decision_id")
    if not isinstance(decision_id, str) or not decision_id:
        raise SystemExit("follow-up event is missing server-generated decision_id")
    if decision_id not in groups:
        groups[decision_id] = []
        order.append(decision_id)
    groups[decision_id].append(line)
if len(order) != 2:
    raise SystemExit(f"follow-up expected two distinct decision IDs, found {len(order)}")
deny_path.write_text("\n".join(groups[order[0]]) + "\n", encoding="utf-8")
allow_path.write_text("\n".join(groups[order[1]]) + "\n", encoding="utf-8")
for path in (deny_path, allow_path):
    os.chmod(path, 0o600)
summary_path.write_text(json.dumps({
    "schema_version": 1,
    "same_service_process_verified": True,
    "distinct_server_generated_decision_ids": 2,
    "request_order": ["p1_deny", "p1_allow"],
    "payloads_persisted": False,
}, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(summary_path, 0o600)
PY
    check_event_log "$deny_log" "$case_dir/p1-deny-structural.json" follow_up_p1_deny || fail "follow-up deny evidence failed"
    check_event_log "$allow_log" "$case_dir/p1-allow-structural.json" follow_up_p1_allow || fail "follow-up allow evidence failed"
    write_case_record "$case_dir/p1-deny-case-input.json" follow_up_p1_deny P1 "$deny_status" "$deny_log" "$deny_probe" "$case_dir/p1-deny-structural.json" same_service_process_two_sequential_requests "" "$case_config" "$deny_probe" not_reached
    write_case_record "$case_dir/p1-allow-case-input.json" follow_up_p1_allow P1 "$allow_status" "$allow_log" "$allow_probe" "$case_dir/p1-allow-structural.json" same_service_process_two_sequential_requests "" "$case_config" "$allow_probe" not_reached
    envoy_pid=; service_pid=; upstream_pid=; envoy_start_token=; service_start_token=; upstream_start_token=
}

# No X-Request-Id or caller transaction identifier is sent.
run_case p1_allow P1 GET /vector/allow "" ""
run_case spoofed_lease_header P1 GET /vector/allow "X-Msconnector-Composite-Lease: client-forged-token" ""
run_case p1_deny P1 GET /vector/p1 "X-Msconnector-Vector: msconnector-p1-only" ""
run_case p2_allow P2 POST /vector/p2-empty "Content-Type: text/plain" ""
run_case p2_deny P2 POST /vector/p2 "Content-Type: text/plain" "msconnector-p2-only"
# Full 33-byte host sample: within Envoy transport capacity, above native limit 32.
run_case p2_oversize P2 POST /vector/p2-body-limit "Content-Type: text/plain" "msconnector-p2-body-limit;bounded"
run_case p3_deny P3 GET /vector/p3 "" ""
run_case p3_redirect P3 GET /vector/p3-redirect "" ""
run_case p4_safe P4 GET /vector/p4-safe "" ""
# Negative host evidence: ext_proc is response-only, so a missing protected
# metadata namespace is detected before client response commitment after the
# upstream response exists. The client must receive a fail-closed 503 and the
# unclaimed retained entry must reach its bounded TTL cleanup.
run_case envoy_response_metadata_omitted NEGATIVE_RESPONSE_METADATA GET /vector/allow "" "" 0 2 envoy.filters.http.ext_authz_missing
# Negative host evidence: the controlled delayed upstream lets the server-side
# lease expire between P2 admission and the first ext_proc response callback.
run_case lease_expired NEGATIVE_EXPIRY GET /vector/allow "" "" 6 10
# Negative host evidence: stop the companion only after the authz lease is
# observed, exercising fail-closed ext_proc unavailability and cleanup.
run_case companion_unavailable NEGATIVE_UNAVAILABLE GET /vector/allow "" "" 1 2 envoy.filters.http.ext_authz 1
run_follow_up_case
strict_case="$RUNTIME_ROOT/cases/p4_strict"; ensure_directory "$strict_case" || fail "unsafe strict case directory"
write_case_record "$strict_case/case-input.json" p4_strict P4 not_run "" "" ""

"$PYTHON_BIN" - "$MATRIX_INPUT" "$RUNTIME_ROOT" "$COMPOSITE_RUNTIME_CONFIG" "$EVENT_LOG_PATH" "$pinned_envoy_release" <<'PY'
import json, os, pathlib, sys
output, root, runtime_config, event_template, release = sys.argv[1:]
payload = {
    "schema_version": 1, "connector": "envoy",
    "integration": "ext_authz_ext_proc_composite", "runtime_root": root,
    "runtime_config": runtime_config, "event_log_template": event_template,
    "envoy_release": release, "correlation": "server_generated_decision_id_only",
    "case_isolation": "fresh_service_process_and_event_log_per_case",
    "payloads_persisted": False,
    "verdict": "lifecycle_only_for_supported_cases_not_catalog_acceptance",
    "host_execution_status": "structural_input_only",
    "shared_verifier": "verify_matrix_evidence.py",
    "shared_verifier_cases": ["p1_allow", "p1_deny", "p2_allow", "p2_deny", "p2_oversize", "p3_deny", "p3_redirect", "p4_safe", "envoy_response_metadata_omitted"],
    "shared_verifier_status": "LIFECYCLE_ONLY_for_supported_cases",
    "catalog_acceptance": False,
    "p4_strict": "not_run_requires_client_visible_reset_or_abort_proof",
    "cases": ["p1_allow", "spoofed_lease_header", "p1_deny", "p2_allow", "p2_deny", "p2_oversize", "p3_deny", "p3_redirect", "p4_safe", "envoy_response_metadata_omitted", "lease_expired", "companion_unavailable", "follow_up_p1_deny", "follow_up_p1_allow", "p4_strict"],
    "follow_up_control": "one_service_process_two_sequential_requests_split_by_server_generated_decision_id",
}
path = pathlib.Path(output)
path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY

trap - EXIT HUP INT TERM
rm -f "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY"
printf 'envoy_composite_matrix: inputs=%s\n' "$MATRIX_INPUT"
