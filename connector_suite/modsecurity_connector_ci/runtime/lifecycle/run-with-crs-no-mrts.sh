#!/bin/sh
: "${TEST_ROOT:?TEST_ROOT is required explicitly}"
# Run exactly one Parent-owned connector through the real CRS/no-MRTS path.
set -eu

CONNECTOR=${1:?connector is required}
RUN_ID=${2:-${CRS_RUNTIME_RUN_ID:-}}
case "$CONNECTOR" in envoy|traefik|lighttpd) ;; *) echo "FAIL: connector must be envoy, traefik, or lighttpd" >&2; exit 2 ;; esac
[ -n "$RUN_ID" ] || RUN_ID="crs-runtime-$(date -u +%Y%m%dT%H%M%SZ)"
case "$RUN_ID" in [A-Za-z0-9]*) ;; *) echo "FAIL: run id must start with ASCII alphanumeric" >&2; exit 2 ;; esac
case "$RUN_ID" in
    *[!A-Za-z0-9._-]*) echo "FAIL: unsafe run id" >&2; exit 2 ;;
    *) : ;;
esac
[ "${#RUN_ID}" -le 48 ] || { echo "FAIL: run id is too long" >&2; exit 2; }

SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
FRAMEWORK_ROOT=${TEST_ROOT:?TEST_ROOT is required explicitly}
PYTHON=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1
TASK_ROOT=${VERIFIED_RUN_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}/ModSecurity-conector-crs-runtime}
RUNTIME_ROOT=$TASK_ROOT/runs/$CONNECTOR/$RUN_ID
BUILD_ROOT=$TASK_ROOT/build/$CONNECTOR/$RUN_ID
COMPONENT_CACHE_ROOT=$TASK_ROOT/cache-v2/shared
EXPECTED_EVIDENCE_ROOT=$TASK_ROOT/evidence
if [ -n "${EVIDENCE_ROOT:-}" ] && [ "$EVIDENCE_ROOT" != "$EXPECTED_EVIDENCE_ROOT" ]; then
    echo "BLOCKED: external EVIDENCE_ROOT is not allowed for with-crs/no-mrts runtime" >&2
    exit 77
fi
EVIDENCE_ROOT=$EXPECTED_EVIDENCE_ROOT
SOURCE_ROOT=$RUNTIME_ROOT/crs-source
CRS_RUNTIME_DIR=$BUILD_ROOT/crs
RULE_PREAMBLE=$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf
ENGINE_RULES=$RUNTIME_ROOT/engine-rules.conf
LISTENER_BASELINE=$RUNTIME_ROOT/listener-baseline.txt
PROCESS_BASELINE=$RUNTIME_ROOT/process-baseline.json
NORMALIZER=$SCRIPT_DIR/normalize-with-crs-no-mrts.py
CONTRACT=$FRAMEWORK_ROOT/ci/checks/catalog/five_connectors_with_crs_no_mrts.py
VERIFIED_RUN_ROOT="$RUNTIME_ROOT"
CONNECTOR_COMPONENT_CACHE="$COMPONENT_CACHE_ROOT"

is_safe_root() {
    value=$1
    case "$value" in /*) ;; *) return 1 ;; esac
    [ "$value" != / ] || return 1
    case "$value" in
        "$CONNECTOR_ROOT"|"$CONNECTOR_ROOT"/*|"$FRAMEWORK_ROOT"|"$FRAMEWORK_ROOT"/*) return 1 ;;
        *) : ;;
    esac
    return 0
}
for root in "$TASK_ROOT" "$BUILD_ROOT" "$RUNTIME_ROOT" "$EVIDENCE_ROOT"; do
    is_safe_root "$root" || { echo "BLOCKED: unsafe external runtime root: $root" >&2; exit 77; }
done
[ -f "$FRAMEWORK_ROOT/ci/provisioning/fetch-crs.sh" ] || { echo "BLOCKED: Framework CRS fetch helper missing" >&2; exit 77; }
[ -f "$FRAMEWORK_ROOT/ci/provisioning/prepare-crs.sh" ] || { echo "BLOCKED: Framework CRS prepare helper missing" >&2; exit 77; }
[ -f "$NORMALIZER" ] || { echo "FAIL: Parent normalizer missing" >&2; exit 1; }
[ -f "$CONTRACT" ] || { echo "BLOCKED: Framework compatibility contract missing" >&2; exit 77; }
"$PYTHON" - "$TASK_ROOT" "$CONNECTOR_ROOT" "$FRAMEWORK_ROOT" <<'PY'
import os, pathlib, stat, sys
for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    current = path
    missing = []
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink(): raise SystemExit(f'unsafe symlink ancestor: {current}')
    for ancestor in [current, *current.parents]:
        if ancestor == pathlib.Path(ancestor.anchor): break
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise SystemExit(f'unsafe runtime ancestor: {ancestor}')
        if info.st_uid != os.geteuid() and stat.S_IMODE(info.st_mode) & (stat.S_IWGRP | stat.S_IWOTH): raise SystemExit(f'world/group writable runtime ancestor: {ancestor}')
PY

mkdir -p "$TASK_ROOT" "$TASK_ROOT/runs/$CONNECTOR" "$TASK_ROOT/build/$CONNECTOR" "$EVIDENCE_ROOT"
[ ! -e "$RUNTIME_ROOT" ] && [ ! -L "$RUNTIME_ROOT" ] || { echo "FAIL: runtime run already exists: $RUNTIME_ROOT" >&2; exit 1; }
[ ! -e "$BUILD_ROOT" ] && [ ! -L "$BUILD_ROOT" ] || { echo "FAIL: build run already exists: $BUILD_ROOT" >&2; exit 1; }
mkdir "$RUNTIME_ROOT" "$BUILD_ROOT"
for path in "$TASK_ROOT" "$BUILD_ROOT" "$RUNTIME_ROOT" "$EVIDENCE_ROOT"; do
    [ ! -L "$path" ] || { echo "BLOCKED: runtime path is a symlink: $path" >&2; exit 77; }
    resolved=$(realpath -e "$path")
    [ "$resolved" = "$path" ] || { echo "BLOCKED: runtime path resolves through a symlink: $path" >&2; exit 77; }
    chmod 700 "$path"
done

# Each CRS acquisition is a fresh Framework checkout.  Source the Framework
# common policy once, then the Parent's guarded fresh-source helper; the
# helpers enforce the reviewed tag, commit, origin, and rule digest.
(
    export CONNECTOR_ROOT FRAMEWORK_ROOT VERIFIED_RUN_ROOT BUILD_ROOT \
        CONNECTOR_COMPONENT_CACHE CACHE_ROOT FULL_MATRIX_MANIFEST
    CACHE_ROOT="$TASK_ROOT/cache-v2"
    FULL_MATRIX_MANIFEST="$RUNTIME_ROOT/crs-manifest.jsonl"
    export CONNECTOR_ROOT FRAMEWORK_ROOT VERIFIED_RUN_ROOT BUILD_ROOT \
        CONNECTOR_COMPONENT_CACHE CACHE_ROOT FULL_MATRIX_MANIFEST
    # shellcheck disable=SC1091
    # Framework path is runtime-selected and pre-validated above.
    . "$FRAMEWORK_ROOT/ci/lib/common.sh"
    export VERIFIED_RUN_ROOT CONNECTOR_COMPONENT_CACHE
    # shellcheck disable=SC1091
    # Parent path is runtime-selected and pre-validated above.
    . "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/prepare-fresh-crs-source.sh"
    sh "$FRAMEWORK_ROOT/ci/provisioning/fetch-crs.sh"
    sh "$FRAMEWORK_ROOT/ci/provisioning/prepare-crs.sh"
)
SOURCE_ROOT="$RUNTIME_ROOT/crs-fresh-source"
CRS_RUNTIME_DIR="$BUILD_ROOT/crs"
RULE_PREAMBLE="$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"

# Check the canonical fixture before any connector process starts.
"$PYTHON" "$FRAMEWORK_ROOT/ci/checks/catalog/five_connectors_with_crs_no_mrts.py" \
    verify-fixture --source-root "$SOURCE_ROOT"

[ ! -e "$BUILD_ROOT/crs-runtime" ] && [ ! -L "$BUILD_ROOT/crs-runtime" ] || {
    echo "FAIL: ambiguous legacy CRS runtime directory exists: $BUILD_ROOT/crs-runtime" >&2
    exit 1
}
[ -f "$RULE_PREAMBLE" ] || { echo "FAIL: Framework did not produce canonical CRS preamble" >&2; exit 1; }
"$PYTHON" - "$RULE_PREAMBLE" "$SOURCE_ROOT" "$CRS_RUNTIME_DIR" <<'PY'
import pathlib, re, sys
preamble, source, runtime = map(pathlib.Path, sys.argv[1:])
if preamble.is_symlink() or not preamble.is_file(): raise SystemExit('CRS preamble is not a regular non-symlink file')
for line in preamble.read_text(encoding='utf-8').splitlines():
    match = re.match(r'^\s*Include\s+"([^"]+)"\s*$', line)
    if match:
        target = pathlib.Path(match.group(1)).resolve(strict=False)
        if not (target == source or source in target.parents or target == runtime or runtime in target.parents):
            raise SystemExit(f'CRS preamble Include escapes verified private roots: {target}')
PY
umask 077
"$PYTHON" - "$ENGINE_RULES" "$RULE_PREAMBLE" <<'PY'
import os, pathlib, sys
output, preamble = map(pathlib.Path, sys.argv[1:])
if output.exists() or output.is_symlink(): raise SystemExit("refusing to overwrite engine rules")
fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, f'SecRuleEngine On\nInclude "{preamble}"\n'.encode())
    os.fsync(fd)
finally:
    os.close(fd)
directory = os.open(output.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
try: os.fsync(directory)
finally: os.close(directory)
PY
MSCONNECTOR_RULES_FILE=$ENGINE_RULES
export CONNECTOR_ROOT FRAMEWORK_ROOT BUILD_ROOT RUNTIME_ROOT MSCONNECTOR_RULES_FILE
export MSCONNECTOR_CRS_RUNTIME=1 CRS_RUNTIME_RUN_ID="$RUN_ID" NO_CRS_RUN_ID="$RUN_ID"
export MODSECURITY_TEST_VARIANT=with-crs MODSECURITY_MRTS_VARIANT=no-mrts
export EXT_PROC_RULES_FILE="$ENGINE_RULES" RUNTIME_COMPONENT_TARGET=shared
HOST_RUNTIME_ROOT="$RUNTIME_ROOT/host"

# Capture the TCP listener set before dispatch.  The post-run scan compares
# against this exact bounded baseline, so an ephemeral host listener cannot be
# mistaken for an unrelated system listener.
"$PYTHON" - "$LISTENER_BASELINE" <<'PY'
import os, pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1])
if out.exists() or out.is_symlink(): raise SystemExit("refusing to overwrite listener baseline")
try:
    data = subprocess.check_output(["ss", "-ltnH"], text=True, stderr=subprocess.PIPE)
except (OSError, subprocess.CalledProcessError) as exc:
    raise SystemExit(f"listener baseline unavailable: {exc}")
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
PY
"$PYTHON" - "$PROCESS_BASELINE" <<'PY'
import json, os, pathlib, sys
out = pathlib.Path(sys.argv[1])
if out.exists() or out.is_symlink(): raise SystemExit("refusing to overwrite process baseline")
records = []
for entry in pathlib.Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        stat_text = (entry / 'stat').read_text(encoding='utf-8')
        closing_parenthesis = stat_text.rfind(')')
        fields = stat_text[closing_parenthesis + 1:].split()
        if closing_parenthesis < 0:
            raise ValueError('missing process comm terminator')
        records.append({'pid': int(entry.name), 'starttime': fields[19], 'ppid': int(fields[1]), 'pgid': int(fields[2])})
    except (FileNotFoundError, ProcessLookupError):
        continue
    except (OSError, ValueError, IndexError) as exc:
        raise SystemExit(f"process baseline inspection unavailable: {exc}")
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as stream:
    json.dump({'process_group': os.getpgrp(), 'processes': records}, stream, sort_keys=True)
    stream.flush(); os.fsync(stream.fileno())
PY

case "$CONNECTOR" in
    envoy) TARGET=runtime-smoke-envoy-ext-proc ;;
    traefik) TARGET=runtime-smoke-traefik-native ;;
    lighttpd) TARGET=runtime-smoke-lighttpd-patched ;;
    *) echo "FAIL: unsupported connector target" >&2; exit 2 ;;
esac
export VERIFIED_RUN_ROOT="$TASK_ROOT" PARENT_HOST_RUNTIME_ROOT="$HOST_RUNTIME_ROOT" \
    BUILD_ROOT CONNECTOR_COMPONENT_CACHE
TRAEFIK_SOCKET_PARENT=
TRAEFIK_SOCKET_PARENT_CLEANUP=not-applicable
cleanup_traefik_socket_parent() {
    [ "$CONNECTOR" = traefik ] || return 0
    [ -n "${TRAEFIK_SOCKET_PARENT:-}" ] || return 0
    [ -d "$TRAEFIK_SOCKET_PARENT" ] && [ ! -L "$TRAEFIK_SOCKET_PARENT" ] || return 1
    [ "$(stat -c '%u' "$TRAEFIK_SOCKET_PARENT")" = "$(id -u)" ] || return 1
    [ "$(stat -c '%a' "$TRAEFIK_SOCKET_PARENT")" = 700 ] || return 1
    rmdir -- "$TRAEFIK_SOCKET_PARENT" || return 1
    TRAEFIK_SOCKET_PARENT=
    TRAEFIK_SOCKET_PARENT_CLEANUP=verified
    export TRAEFIK_SOCKET_PARENT_CLEANUP
}
if [ "$CONNECTOR" = traefik ]; then
    TRAEFIK_SOCKET_PARENT=
    for socket_parent_base in /dev/shm /tmp; do
        if candidate=$(mktemp -d "$socket_parent_base/msconnector-traefik-uds.XXXXXX" 2>/dev/null); then
            TRAEFIK_SOCKET_PARENT=$candidate
            break
        fi
    done
    [ -n "$TRAEFIK_SOCKET_PARENT" ] || { echo 'BLOCKED: no safe Traefik socket-parent filesystem available' >&2; exit 77; }
    status=0
    trap 'status=$?; cleanup_traefik_socket_parent || status=1; exit "$status"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    [ -d "$TRAEFIK_SOCKET_PARENT" ] && [ ! -L "$TRAEFIK_SOCKET_PARENT" ] || { echo 'FAIL: unsafe Traefik socket parent' >&2; exit 1; }
    [ "$(stat -c '%u' "$TRAEFIK_SOCKET_PARENT")" = "$(id -u)" ] || { echo 'FAIL: foreign Traefik socket parent' >&2; exit 1; }
    [ "$(stat -c '%a' "$TRAEFIK_SOCKET_PARENT")" = 700 ] || { echo 'FAIL: Traefik socket parent mode is not 0700' >&2; exit 1; }
    export TRAEFIK_ENGINE_SOCKET_PARENT="$TRAEFIK_SOCKET_PARENT"
fi
case "$CONNECTOR" in
    envoy) export ENVOY_EXT_PROC_RUNTIME_ROOT="$HOST_RUNTIME_ROOT" ;;
    traefik) export TRAEFIK_NATIVE_RUNTIME_ROOT="$HOST_RUNTIME_ROOT" ;;
    lighttpd)
        export NO_CRS_ARTIFACT_PROFILE=full_lifecycle FULL_LIFECYCLE_HOST_PROFILE=patched-native \
            FULL_LIFECYCLE_EXECUTED_TARGET="$TARGET" FULL_LIFECYCLE_EVIDENCE_OUTPUT="$HOST_RUNTIME_ROOT/first-byte-evidence.json" \
            LIGHTTPD_PATCHED_SMOKE_DIR="$HOST_RUNTIME_ROOT"
        ;;
    *) echo "FAIL: unsupported connector environment" >&2; exit 2 ;;
esac
set +e
"$PYTHON" - "$TEST_ROOT/connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-remaining-connector-target.sh" "$CONNECTOR" "$TARGET" <<'PY'
import ctypes, os, pathlib, signal, subprocess, sys, time

PR_SET_CHILD_SUBREAPER = 36
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    raise SystemExit(f"cannot establish child subreaper: errno={ctypes.get_errno()}")

def identity(pid):
    text = (pathlib.Path('/proc') / str(pid) / 'stat').read_text(encoding='utf-8')
    close = text.rfind(')')
    if close < 0:
        raise ValueError('missing process comm terminator')
    fields = text[close + 1:].split()
    return int(fields[1]), int(fields[2]), fields[19]

def descendants(root_pid):
    records = {}
    for entry in pathlib.Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            ppid, _pgid, start = identity(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, IndexError) as exc:
            raise SystemExit(f'child ownership inspection unavailable: {exc}')
        records[int(entry.name)] = (ppid, start)
    found = set()
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _start) in records.items():
            if (ppid == root_pid or ppid in found) and pid not in found:
                found.add(pid); changed = True
    return {(pid, records[pid][1]) for pid in found}

child_env = os.environ.copy()
child_env['TAR_OPTIONS'] = '--no-same-owner'
child = subprocess.Popen(['sh', sys.argv[1], sys.argv[2], sys.argv[3]], env=child_env)
owned = set()
while child.poll() is None:
    owned.update(descendants(child.pid))
    time.sleep(0.05)
owned.update(descendants(child.pid))
try:
    status = child.wait()
except ChildProcessError:
    status = 1
owned.update(descendants(os.getpid()))

def reap_bounded(duration):
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        reaped = False
        while True:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
            reaped = True
        if not reaped:
            time.sleep(0.02)

def signal_owned(pid, start, sig):
    try:
        _ppid, _pgid, current_start = identity(pid)
    except (FileNotFoundError, ProcessLookupError):
        return
    except (OSError, ValueError, IndexError) as exc:
        raise SystemExit(f'process identity revalidation unavailable: {exc}')
    if current_start != start:
        raise SystemExit('process identity changed before signal')
    if hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'):
        try:
            pidfd = os.pidfd_open(pid)
            try:
                _ppid, _pgid, opened_start = identity(pid)
                if opened_start != start:
                    raise SystemExit('process identity changed after pidfd open')
                signal.pidfd_send_signal(pidfd, sig)
            finally:
                os.close(pidfd)
            return
        except ProcessLookupError:
            return
        except OSError:
            # Fall through only after the same strict identity check below.
            pass
    try:
        _ppid, _pgid, current_start = identity(pid)
    except (FileNotFoundError, ProcessLookupError):
        return
    except (OSError, ValueError, IndexError) as exc:
        raise SystemExit(f'process identity revalidation unavailable: {exc}')
    if current_start != start:
        raise SystemExit('process identity changed before fallback signal')
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return

remaining = set()
for sig, rounds, wait_time in ((signal.SIGTERM, 20, 0.1), (signal.SIGKILL, 10, 0.05)):
    for _round in range(rounds):
        reap_bounded(0.05)
        current = descendants(child.pid) | descendants(os.getpid())
        remaining.update(current)
        if not current:
            break
        for pid, start in current:
            signal_owned(pid, start, sig)
        reap_bounded(wait_time)
        time.sleep(wait_time)
    else:
        continue
    break
reap_bounded(0.5)
remaining = descendants(child.pid) | descendants(os.getpid())
if remaining:
    raise SystemExit('task-owned descendant survived bounded cleanup')
if status < 0:
    raise SystemExit(128 - status)
raise SystemExit(status)
PY
dispatch_status=$?
set -e
if [ "$CONNECTOR" = traefik ]; then
    cleanup_traefik_socket_parent || dispatch_status=1
fi
[ "$dispatch_status" -eq 0 ] || exit "$dispatch_status"

# The host harness owns shutdown, but the dispatcher independently checks the
# resulting process/socket state before any evidence is normalized.
if find "$RUNTIME_ROOT/host" \( -type s -o -type f -name '*.pid' \) -print -quit | grep -q .; then
    echo "FAIL: connector cleanup left a socket or pid file" >&2
    exit 1
fi
if find "$RUNTIME_ROOT/host" -iname '*mrts*' -print -quit | grep -q .; then
    echo "FAIL: runtime root contains an MRTS artifact" >&2
    exit 1
fi
"$PYTHON" - "$RUNTIME_ROOT/host/runtime-observation.json" "$RUNTIME_ROOT/host" "$CONNECTOR" "$LISTENER_BASELINE" "$PROCESS_BASELINE" <<'PY'
import json, os, pathlib, stat, subprocess, sys
out, root = map(pathlib.Path, sys.argv[1:3])
connector = sys.argv[3]
baseline_path = pathlib.Path(sys.argv[4])
process_baseline_path = pathlib.Path(sys.argv[5])
mode = {'envoy': 'ext_proc', 'traefik': 'native-traefik-middleware', 'lighttpd': 'patched-native-lighttpd'}[connector]
artifacts = [p for p in root.rglob('*') if 'mrts' in p.name.lower()]
try:
    baseline = json.loads(process_baseline_path.read_text(encoding='utf-8'))
    baseline_ids = {(int(item['pid']), str(item['starttime'])) for item in baseline['processes']}
    process_group = int(baseline['process_group'])
except (OSError, ValueError, KeyError, TypeError) as exc:
    raise SystemExit(f'process baseline unavailable: {exc}')
try:
    process_lines = subprocess.check_output(['ps', '-eo', 'pid=,args='], text=True).splitlines()
except (OSError, subprocess.CalledProcessError) as exc:
    raise SystemExit(f'process inspection unavailable: {exc}')
excluded = {os.getpid()}
cursor = os.getpid()
while cursor > 1:
    stat_path = pathlib.Path('/proc') / str(cursor) / 'stat'
    try:
        stat_text = stat_path.read_text(encoding='utf-8')
        closing_parenthesis = stat_text.rfind(')')
        fields_after_comm = stat_text[closing_parenthesis + 1:].split()
        if closing_parenthesis < 0:
            raise ValueError('missing process comm terminator')
        # /proc/<pid>/stat is ``pid (comm) state ppid ...``.  Parse after the
        # final ')' so an unusual but legal comm name cannot shift ppid.
        parent = int(fields_after_comm[1])
    except (FileNotFoundError, ProcessLookupError):
        break
    except (OSError, ValueError, IndexError) as exc:
        raise SystemExit(f'process ancestry inspection unavailable: {exc}')
    if parent <= 0 or parent in excluded:
        break
    excluded.add(parent)
    cursor = parent
processes = []
for line in process_lines:
    try:
        pid_text, command = line.strip().split(None, 1)
        pid = int(pid_text)
    except (ValueError, IndexError):
        continue
    stat_path = pathlib.Path('/proc') / str(pid) / 'stat'
    try:
        stat_text = stat_path.read_text(encoding='utf-8')
        closing_parenthesis = stat_text.rfind(')')
        fields = stat_text[closing_parenthesis + 1:].split()
        if closing_parenthesis < 0:
            raise ValueError('missing process comm terminator')
        starttime = str(fields[19]); pgid = int(fields[2])
    except (FileNotFoundError, ProcessLookupError):
        continue
    except (OSError, ValueError, IndexError) as exc:
        raise SystemExit(f'process identity inspection unavailable: {exc}')
    is_new_owned = pgid == process_group and (pid, starttime) not in baseline_ids
    if pid in excluded or (str(root) not in command and not is_new_owned):
        continue
    processes.append(command)
mrts_processes = [line for line in processes if 'mrts' in line.lower() or 'modsecurity-test-framework/tools/mrts' in line.lower()]
host_processes = [line for line in processes if connector in line.lower()]
helper_processes = [line for line in processes if line not in host_processes]
sockets = [p for p in root.rglob('*') if p.is_socket()]
pid_files = [p for p in root.rglob('*.pid') if p.is_file()]
temporary = [p for p in root.rglob('*') if p.name.endswith(('.tmp', '.partial'))]
fixtures = [p for p in root.rglob('*') if p.name in ('entity-fixtures', 'plugins-local', 'effective-config', 'engine-build', 'tmp')]
try:
    unix_output = subprocess.check_output(['ss', '-lx'], text=True, stderr=subprocess.PIPE)
    tcp_output = subprocess.check_output(['ss', '-ltnH'], text=True, stderr=subprocess.PIPE)
except (OSError, subprocess.CalledProcessError) as exc:
    raise SystemExit(f'listener inspection unavailable: {exc}')
baseline = set(baseline_path.read_text(encoding='utf-8').splitlines())
new_tcp = [line for line in tcp_output.splitlines() if line not in baseline]
listeners = [line for line in unix_output.splitlines() if str(root) in line] + new_tcp
no_mrts = {'runner_invoked': bool(mrts_processes), 'case_inventory_loaded': bool(artifacts), 'process_started': bool(mrts_processes), 'socket_or_listener_created': bool(artifacts) or bool(listeners), 'artifact_used': bool(artifacts)}
cleanup_ok = not processes and not artifacts and not listeners and not sockets and not pid_files and not fixtures and not temporary
payload = {'schema_version': 1, 'record_type': 'runtime_observation', 'runtime_root': str(root), 'external_socket_parent_cleanup': os.environ.get('TRAEFIK_SOCKET_PARENT_CLEANUP', 'not-applicable'), 'cleanup': {'processes_remaining': len(processes), 'host_processes_remaining': len(host_processes), 'helper_processes_remaining': len(helper_processes), 'listeners_remaining': len(listeners), 'sockets_remaining': len(sockets), 'pid_files_remaining': len(pid_files), 'runtime_fixtures_remaining': len(fixtures), 'temporary_paths_remaining': len(temporary), 'paths': [str(p) for p in sockets + pid_files + fixtures + temporary], 'listener_records': listeners}, 'cleanup_status': 'PASS' if cleanup_ok else 'FAIL', 'no_mrts': {**no_mrts, 'unexpected_artifacts': [str(p) for p in artifacts], 'unexpected_processes': mrts_processes}, 'dispatch': {'source': 'parent-runner', 'connector': connector, 'integration_mode': mode, 'test_variant': 'with-crs', 'mrts_variant': 'no-mrts'}, 'status': 'PASS' if cleanup_ok and not any(no_mrts.values()) else 'FAIL'}
if out.exists() or out.is_symlink(): raise SystemExit('refusing to overwrite runtime observation')
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as stream: json.dump(payload, stream, sort_keys=True); stream.write('\n')
PY

"$PYTHON" "$NORMALIZER" --connector "$CONNECTOR" --run-id "$RUN_ID" \
    --runtime-root "$RUNTIME_ROOT/host" --evidence-root "$EVIDENCE_ROOT" \
    --source-root "$SOURCE_ROOT" --connector-root "$CONNECTOR_ROOT" \
    --framework-root "$FRAMEWORK_ROOT"

# Compatibility validation is mandatory, but its UNATTESTED host status is not
# a Parent success signal.  The normalizer's PASS is the host-runtime result.
"$PYTHON" "$CONTRACT" validate --evidence-root "$EVIDENCE_ROOT" \
    --source-root "$SOURCE_ROOT" --connector "$CONNECTOR" --run-id "$RUN_ID"
echo "crs_runtime_no_mrts: pass connector=$CONNECTOR run_id=$RUN_ID"
