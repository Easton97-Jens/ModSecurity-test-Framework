"""Run each bound original native fixture; collect, never qualify measurements."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import time
from types import SimpleNamespace

import base_driver as base

TASK = Path('/task')
FIXTURES = Path('/mnt/fixtures')
MANIFEST = FIXTURES / 'acceptance-manifest.json'
FAULT_SYMBOLS = ('openat', 'setvbuf', 'fputs', 'fflush', 'fclose', 'msconnector_generic_map_request')
NEIGHBOR_BATCH_SIZE = 8
PYTHON = '/usr/local/bin/python3'
CLIENT_SCRIPT = 'acceptance_client.py'
READINESS_SUFFIX = '-readiness.json'
ROUTERS = '  routers:\n'
SAFE_MODE = 'phase4_mode=safe'
HOST_LIFECYCLE = 'host-lifecycle.jsonl'
EVENTS = 'events.jsonl'
PROXY_SOCKET = '/task/sockets/proxy.sock'


def fault_mode(case):
    name = case['id'].split('::')[-1]
    return {'body_size_nonzero_with_null_data': 'mapper-body-null',
            'header_count_nonzero_with_null_headers': 'mapper-headers-null',
            'early_mapping_failure_cleanup': 'mapper-headers-null',
            'transaction_begin_failure_cleanup': 'begin-failure',
            'finish_failure_propagation': 'finish-failure',
            'NEED-invalid-native-return': 'native-invalid-return'}.get(name,
            'sink-' + name.removeprefix('NEED-physical-event-sink-') if name.startswith('NEED-physical-event-sink-') else '')


def stop(_label, process, marker):
    record = {'proxy_pid': process.pid}
    if process.poll() is None:
        pid = base.actual_pid(process, marker)
        record['actual_pid'] = pid
        os.kill(pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.kill(pid, signal.SIGKILL)
            process.wait(timeout=5)
            record['graceful_timeout'] = True
    record['exit_code'] = process.returncode
    return record


def command(label, argv, env, pass_fds=(), timeout_seconds=30, absolute_deadline=None):
    if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ValueError('finite positive command deadline <=120 required')
    command_line = ['rtk', 'proxy', *map(str, argv)]
    started = time.monotonic_ns()
    failure = None
    with (TASK / (label + '.stdout')).open('wb') as stdout, (TASK / (label + '.stderr')).open('wb') as stderr:
        result = subprocess.Popen(command_line, cwd=base.SOURCE, env=env, stdout=stdout, stderr=stderr,
            pass_fds=pass_fds, start_new_session=True)
        try:
            wait_budget = timeout_seconds if absolute_deadline is None else min(timeout_seconds, absolute_deadline - time.monotonic())
            if wait_budget <= 0:
                raise subprocess.TimeoutExpired(command_line, 0)
            result.wait(timeout=wait_budget)
        except subprocess.TimeoutExpired as error:
            failure = error
            try:
                os.killpg(result.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass  # A child can exit between deadline expiry and signaling.
            try:
                result.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(result.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                result.wait(timeout=5)
    receipt = {'argv': command_line, 'exit_code': result.returncode, 'wrapper_pid': result.pid,
               'timed_out': failure is not None,
               'absolute_work_deadline': absolute_deadline, 'wait_budget_seconds': max(0, wait_budget),
               'started_ns': started, 'completed_ns': time.monotonic_ns(),
               'signal': -result.returncode if result.returncode < 0 else None,
               'stdout_sha256': base.digest(TASK / (label + '.stdout')),
               'stderr_sha256': base.digest(TASK / (label + '.stderr'))}
    base.write(label + '.command.json', receipt)
    if failure is not None:
        raise failure
    return receipt


def native_control_counts(path, transaction_id, offset):
    with path.open('rb') as stream:
        stream.seek(offset)
        raw = stream.read()
    rows = []
    malformed = 0
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            if row.get('transaction_id') == transaction_id:
                rows.append(row)
        except (ValueError, AttributeError):
            malformed += 1
    returns = [row for row in rows if row.get('edge') == 'return']
    return {'native_allocations': sum(row.get('result') == 1 for row in returns
                    if row.get('function') in ('native_new', 'native_new_with_id')),
        'native_cleanup_returns': sum(row.get('function') == 'native_cleanup' for row in returns),
        'native_logging_returns': sum(row.get('function') == 'native_process_logging' for row in returns),
        'native_logging_successes': sum(row.get('function') == 'native_process_logging' and row.get('result') == 1 for row in returns),
        'runtime_request_eos_returns': sum(row.get('function') == 'runtime_finish_request_body' for row in returns),
        'runtime_response_eos_returns': sum(row.get('function') == 'runtime_finish_response_body' for row in returns),
        'native_pids': sorted({row['pid'] for row in rows}),
        'invalid_rows': sum(row.get('invalid') is not False for row in rows), 'malformed_rows': malformed}


def http_readiness(case, port, env, lifecycle_path, host_pid):
    deadline = time.monotonic() + 30
    receipt = {'key': case['key'], 'actual_host_pid': host_pid, 'route': 'independent healthy neighbor',
               'qualified_main_control': False, 'attempts': [], 'ready': False}
    for index, identity in enumerate(case['readiness_ids']):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        label = case['key'] + '-readiness-' + str(index)
        key = 'neighbor-readiness-' + str(index) + '-' + case['key']
        offset = lifecycle_path.stat().st_size
        attempt = {'transaction_id': identity, 'key': key, 'native_log_start': offset,
            'command': command(label, [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT,
                        port, MANIFEST, case['key'], 'readiness-' + str(index)], env,
                        timeout_seconds=min(10, remaining), absolute_deadline=deadline)}
        client_path = TASK / 'client' / (key + '.receipt.json')
        client = json.loads(client_path.read_text())
        attempt.update(client_receipt=str(client_path), actual_status=client.get('status'))
        receipt['attempts'].append(attempt)
        base.write(case['key'] + READINESS_SUFFIX, receipt)
        if client.get('status') == 404:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.05, remaining))
            continue
        if client.get('status') != 200:
            raise RuntimeError('HTTP readiness returned a non-startup error; preserved receipts')
        if await_native_readiness(case, lifecycle_path, identity, offset, deadline, attempt, receipt):
            return receipt
        break
    base.write(case['key'] + READINESS_SUFFIX, receipt)
    raise RuntimeError('HTTP/native readiness deadline reached; no qualified beforecontrol executed')


def neighbor_scope_status(path, batch, final=False):
    with path.open('rb') as stream:
        stream.seek(batch['native_log_start'])
        raw = stream.read()
    rows, malformed = [], 0
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            if row.get('pid') == batch['pid']:
                rows.append(row)
        except (ValueError, AttributeError):
            malformed += 1
    sequences = [row.get('sequence') for row in rows]
    admitted = bool(rows and rows[0].get('function') == 'observer' and rows[0].get('edge') == 'admitted')
    complete = admitted and sequences == list(range(1, len(rows) + 1)) and not malformed and all(row.get('invalid') is False for row in rows)
    returns = [row for row in rows if row.get('edge') == 'return']
    allocations = [row for row in returns if row.get('function') in ('native_new', 'native_new_with_id') and row.get('result') == 1]
    scopes = []
    for allocation in allocations:
        scope_record = allocation_scope_status(allocation, returns)
        scopes.append(scope_record)
        complete = complete and scope_record['complete']
    if len({scope['allocation_scope_call'] for scope in scopes}) != len(scopes):
        complete = False
    final_row = rows[-1] if rows else {}
    if final:
        complete = complete and final_row.get('function') == 'observer' and final_row.get('edge') == 'final' and final_row.get('live_mappings') == 0
    return {'pid': batch['pid'], 'native_log_start': batch['native_log_start'], 'native_log_end': batch['native_log_start'] + len(raw),
        'window_sha256': hashlib.sha256(raw).hexdigest(), 'rows': len(rows), 'malformed_rows': malformed,
        'scopes': scopes, 'final_required': final, 'final_row': final_row, 'complete': bool(complete)}


def prepare_neighbor_batch(execution_index, batch, lifecycle_path, socket_path, stop_current, start_new):
    if batch is not None:
        before = neighbor_scope_status(lifecycle_path, batch)
        base.write('neighbor-reuse-' + str(execution_index) + '.json', before)
        if not before['complete']:
            raise RuntimeError('Previous neighbor scopes are incomplete; observer reuse refused')
        if execution_index % NEIGHBOR_BATCH_SIZE:
            return batch
        stopped = stop_current()
        native = neighbor_scope_status(lifecycle_path, batch, final=True)
        receipt = {'batch': batch, 'process': stopped, 'native': native, 'socket_removed': not socket_path.exists()}
        base.write('neighbor-batch-' + str(batch['batch_index']) + '-final.json', receipt)
        if stopped['exit_code'] != 0 or not native['complete'] or not receipt['socket_removed']:
            raise RuntimeError('Neighbor observer final/cleanup proof missing; rotation refused')
    next_index = 0 if batch is None else batch['batch_index'] + 1
    created = start_new(next_index)
    base.write('neighbor-batch-' + str(next_index) + '-start.json', created)
    return created


def dynamic_config(helper, path, backend_port, main_socket, neighbor_socket, reuse_socket,
                   file_target=None):
    helper.write_dynamic_config(path, backend_port, main_socket)
    text = path.read_text()
    text = text.replace(ROUTERS, '  routers:\n    neighbor:\n      entryPoints: [web]\n'
        '      rule: "PathPrefix(`/i12/neighbor/`)"\n      priority: 100\n'
        '      middlewares: [neighbor]\n      service: upstream\n', 1)
    text = text.replace(ROUTERS, '  routers:\n    reuse:\n      entryPoints: [web]\n'
        '      rule: "PathPrefix(`/i12/reuse/`)"\n      priority: 90\n'
        '      middlewares: [reuse]\n      service: upstream\n', 1)
    text = text.replace('  middlewares:\n', '  middlewares:\n    neighbor:\n      plugin:\n'
        '        modsecurityNative:\n          maxHeaderCount: 128\n          maxHeaderBytes: 65536\n'
        '          maxRequestChunkBytes: 32768\n          maxResponseChunkBytes: 32768\n'
        '          transactionIDHeader: X-Request-Id\n          engineMode: uds\n'
        '          engineSocketPath: ' + json.dumps(str(neighbor_socket)) + '\n', 1)
    text = text.replace('  middlewares:\n', '  middlewares:\n    reuse:\n      plugin:\n'
        '        modsecurityNative:\n          maxHeaderCount: 128\n          maxHeaderBytes: 65536\n'
        '          maxRequestChunkBytes: 32768\n          maxResponseChunkBytes: 32768\n'
        '          transactionIDHeader: X-Request-Id\n          engineMode: uds\n'
        '          engineSocketPath: ' + json.dumps(str(reuse_socket)) + '\n', 1)
    if file_target is not None:
        key, port = file_target
        if (not isinstance(key, str) or not key or len(key) > 100 or
                any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in key) or
                type(port) is not int or not 1 <= port <= 65535):
            raise ValueError('literal file target key and loopback port required')
        text = text.replace(ROUTERS, '  routers:\n    file-target:\n'
            '      entryPoints: [web]\n      rule: "Header(`X-I12-Acceptance-Key`, `' + key + '`)"\n'
            '      priority: 200\n      middlewares: [modsecurity]\n      service: file-target\n', 1)
        # Reuse the exact main middleware name from the current helper contract.
        baseline = path.read_text()
        import re
        main_middlewares = re.findall(r'^ {6}middlewares: (.+)$', baseline, re.MULTILINE)
        if len(main_middlewares) != 1:
            raise ValueError('exact baseline main middleware required')
        text = text.replace('      middlewares: [modsecurity]\n      service: file-target',
            '      middlewares: ' + main_middlewares[0] + '\n      service: file-target', 1)
        text = text.replace('  services:\n', '  services:\n    file-target:\n      loadBalancer:\n'
            '        servers:\n          - url: "http://127.0.0.1:' + str(port) + '"\n', 1)
    path.write_text(text)


def stage_file_execution(case, root, env):
    supplement = case['fixture'].get('file_supplement')
    if supplement is None:
        return None
    validate_file_identity(case)
    source_root, evidence_root = root / 'file-source', root / 'file-evidence'
    source_root.mkdir(mode=0o700)
    evidence_root.mkdir(mode=0o700)
    manifest = FIXTURES / 'i12-file-source/manifest.json'
    if base.digest(manifest) != supplement['manifest_sha256'] or base.digest(FIXTURES / 'i12_file/supplement-plan.json') != supplement['supplement_plan_sha256']:
        raise ValueError('file supplement differs from sealed manifest/plan')
    files = json.loads(manifest.read_text())['files']
    if [spec for spec in files if spec['relative_path'] == supplement['fixture']] != [supplement['file_spec']]:
        raise ValueError('file supplement spec differs from sealed fixture')
    arguments = [PYTHON, '-P', FIXTURES / 'i12_file/run.py']
    # Safe-path suppresses script-directory imports. Bind this child alone to
    # the controller's read-only sealed sibling-source directory instead.
    file_env = env | {'PYTHONPATH': str(FIXTURES / 'i12_file')}
    shared = ['--manifest', manifest, '--private-root', source_root, '--evidence-root', evidence_root]
    staged = command(case['key'] + '-file-stage', arguments + ['stage', *shared,
        '--fixture-root', FIXTURES / 'i12-file-source'], file_env)
    if staged['exit_code'] != 0:
        raise RuntimeError('physical source staging failed')
    return {'argv': arguments, 'shared': shared, 'evidence_root': evidence_root,
            'staging': staged, 'supplement': supplement, 'env': file_env}


def validate_file_identity(case):
    identity, key = case.get('transaction_id'), case.get('key')
    for value in (identity, key):
        if (not isinstance(value, str) or not 1 <= len(value) <= 100 or
                any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in value)):
            raise ValueError('distinct sealed file key and transaction ID required')
    if identity == key:
        raise ValueError('file correlation key must differ from native transaction ID')


def file_process_argv(execution, mode, port, case):
    validate_file_identity(case)
    if mode not in ('client', 'backend'):
        raise ValueError('literal file HTTP mode required')
    argv = execution['argv'] + [mode, *execution['shared'], '--port', port,
        '--key', case['key'], '--transaction-id', case['transaction_id'],
        '--fixture', execution['supplement']['fixture']]
    if mode == 'client':
        argv += ['--uri', case['fixture']['request']['uri']]
    return argv


def strict_configuration(text):
    if text.count(SAFE_MODE) != 1:
        raise ValueError('exactly one Safe phase4 configuration required for Strict negative')
    return text.replace(SAFE_MODE, 'phase4_mode=strict', 1)


def file_backend_ready(process, marker, evidence_root, key, port, timeout=10):
    """Observe bind/listen metadata without consuming the single target accept."""
    deadline = time.monotonic() + timeout
    path = evidence_root / (key + '.backend-listening.json')
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('file backend exited before listening')
        if path.is_file():
            if path.stat().st_size > 4096:
                raise ValueError('bounded file backend listening receipt required')
            try:
                receipt = json.loads(path.read_text())
            except json.JSONDecodeError:
                time.sleep(0.02)
                continue  # The live child can still be writing its fresh receipt.
            if receipt.get('port') != port or receipt.get('pid') != base.actual_pid(process, marker):
                raise ValueError('file backend listening PID/port mismatch')
            return receipt
        time.sleep(0.02)
    raise RuntimeError('file backend listening receipt deadline reached')


def append_rules(path, fixture, log_root):
    lines = list(fixture['rules_lines'])
    # Audit/debug destination relocation only. Product rules/body policies stay
    # exactly fixture-bound; their source digest is recorded separately.
    lines = [line for line in lines if not line.lstrip().startswith(('SecAuditLog ', 'SecAuditLogStorageDir ', 'SecDebugLog '))]
    lines += ['SecAuditEngine On', 'SecAuditLogType Serial', 'SecAuditLogParts ABCEFHJKZ',
              'SecAuditLog ' + str(log_root / 'audit.log'), 'SecDebugLog ' + str(log_root / 'debug.log'), 'SecDebugLogLevel 9']
    path.write_text('\n'.join(lines) + '\n')


class CaseExecution:
    """One original fixture owns its services, faults and physical cleanup."""

    def __init__(self, case, runtime):
        self.case = case
        self.runtime = runtime

    def execute(self):
        self.key = self.case['key']
        self.root = TASK / 'cases' / self.key
        self.root.mkdir(mode=0o700)
        self.fixture = self.case['fixture']
        self.result = {'id': self.case['id'], 'key': self.key, 'fixture_sha256': self.case['fixture_sha256'],
            'started_ns': time.monotonic_ns(), 'qualification': None,
            'contract_blockers': self.case['contract_blockers'], 'processes': {},
            'native_log_start': self.runtime.lifecycle_path.stat().st_size, 'host_log_start': self.runtime.host_path.stat().st_size}
        self.processes = {}
        self.socket_dir = self.runtime.helper.create_private_engine_socket_dir(self.runtime.inputs.engine_socket_parent)
        self.engine_socket = self.socket_dir.path / self.runtime.helper.ENGINE_SOCKET_FILENAME
        self.fault_fd = os.open(self.root / 'faults.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.proxy_identity = None
        try:
            self.stage_file()
            self.configure()
            if self.case['classification'] == 'config':
                self.result['configtest'] = command(self.key + '-configtest', [self.runtime.engine, '--check-config', '--config', self.config],
                    self.runtime.native_env | {'MSCONNECTOR_LIFECYCLE_CASE': self.case['id']}, (self.runtime.lifecycle_fd,))
                self.result['configuration'] = {str(p): base.digest(p) for p in (self.config, self.rules_path)}
                self.result['configuration_only'] = True
                return self.result
            self.prepare_neighbor()
            self.configure_environment()
            self.startup_control()
            self.start_engine()
            self.start_host()
            self.before_controls()
            self.target_traffic()
            # A failed target must never suppress independent neighbor evidence.
            time.sleep(0.2)
            base.snapshot(self.key + '-after', self.runtime.persistent | {name: value for name, value in self.processes.items() if value[0].poll() is None})
        except Exception as error:
            self.result['execution_error'] = {'type': type(error).__name__, 'message': str(error)}
        finally:
            self.cleanup()
            self.result['completed_ns'] = time.monotonic_ns()
            os.close(self.fault_fd)
            (self.root / 'measurement.json').write_text(json.dumps(self.result, indent=2) + '\n')
        return self.result

    def stage_file(self):
        self.file_execution = stage_file_execution(self.case, self.root, self.runtime.env)
        self.file_target = None
        if self.file_execution is not None:
            self.result['physical_file'] = {'staging': self.file_execution['staging'],
                'evidence_root': str(self.file_execution['evidence_root']),
                'native_file_api': False, 'qualification': None,
                'backend_exclusion_expected': False}
            if self.file_execution['supplement']['physical_reader'] == 'backend':
                file_port = self.runtime.helper.free_port()
                file_script = FIXTURES / 'i12_file/run.py'
                file_backend = base.start(self.key + '-file-backend',
                    file_process_argv(self.file_execution, 'backend', file_port, self.case), self.file_execution['env'], self.runtime.handles)
                self.processes['file-backend'] = (file_backend, str(file_script))
                self.result['physical_file']['listening'] = file_backend_ready(file_backend,
                    str(file_script), self.file_execution['evidence_root'], self.key, file_port)
                self.file_target = (self.key, file_port)

    def configure(self):
        self.rules_path, self.config = self.root / 'rules.conf', self.root / 'engine.conf'
        append_rules(self.rules_path, self.fixture, self.root)
        self.runtime.helper.write_engine_config(self.config, self.rules_path, self.root / EVENTS)
        self.config.write_text(self.config.read_text().replace(SAFE_MODE, 'phase4_mode=' + self.fixture['policy']['phase4_mode']))
        if self.fixture.get('max_event_json_bytes') is not None:
            limit = self.fixture['max_event_json_bytes']
            if not isinstance(limit, int) or not 1 <= limit <= 16384:
                raise ValueError('event capacity outside current product limit')
            self.config.write_text(self.config.read_text().replace('max_event_json_bytes=16384', 'max_event_json_bytes=' + str(limit)))
        if self.case['id'].endswith('unsafe_event_path'):
            unsafe = self.root / 'unsafe-event-directory'
            unsafe.mkdir(mode=0o777)
            self.config.write_text(self.config.read_text().replace(str(self.root / EVENTS), str(unsafe)))

    def prepare_neighbor(self):
        self.runtime.neighbor_batch = prepare_neighbor_batch(self.runtime.neighbor_uses, self.runtime.neighbor_batch, self.runtime.lifecycle_path,
            self.runtime.neighbor_socket, self.runtime.stop_neighbor_batch, self.runtime.start_neighbor_batch)
        self.runtime.neighbor_uses += 1
        self.result['neighbor_batch'] = self.runtime.neighbor_batch
        for mode in self.fixture.get('literal_negative_config_modes', []):
            negative_config = self.root / ('negative-' + mode + '.conf')
            negative_config.write_text(self.config.read_text().replace('phase4_mode=off', 'phase4_mode=' + mode))
            self.result['literal_negative_config'] = command(self.key + '-negative-' + mode,
                [self.runtime.engine, '--check-config', '--config', negative_config],
                self.runtime.native_env | {'MSCONNECTOR_LIFECYCLE_CASE': self.case['id'] + '::negative-minimal'}, (self.runtime.lifecycle_fd,))

    def configure_environment(self):
        self.engine_env = self.runtime.native_env | {'MSCONNECTOR_LIFECYCLE_CASE': self.case['id'],
            'I12_ACCEPTANCE_FAULT': fault_mode(self.case), 'I12_ACCEPTANCE_FAULT_FD': str(self.fault_fd),
            'I12_ACCEPTANCE_FAULT_URI': self.fixture['request']['uri'],
            'I12_ACCEPTANCE_EVENT_PATH': str(self.root / EVENTS)}
        self.host_env = dict(self.runtime.env)
        self.host_env.pop('I12_NATIVE_GENERATED_CASE', None)
        if self.fixture['request'].get('omit_transaction_id'):
            if self.key != '004-b044cc412aca':
                raise ValueError('unreviewed generated-ID capture case')
            self.host_env['I12_NATIVE_GENERATED_CASE'] = self.key
        self.result['generated_id_child_environment'] = {'name': 'I12_NATIVE_GENERATED_CASE',
            'present': 'I12_NATIVE_GENERATED_CASE' in self.host_env,
            'value': self.host_env.get('I12_NATIVE_GENERATED_CASE'), 'dedicated_host': True}

    def startup_control(self):
        if fault_mode(self.case) == 'sink-open':
            # Healthy same-image service controls must bracket the actual
            # constructor failure, not merely the later client request.
            dynamic_config(self.runtime.helper, self.runtime.artifacts.dynamic_config, self.runtime.backend_port, self.engine_socket, self.runtime.neighbor_socket, self.engine_socket)
            self.runtime.helper.write_static_config(self.runtime.artifacts.static_config, self.runtime.artifacts.dynamic_config, self.runtime.host_port, self.runtime.inputs.module_name)
            pre_host = base.start(self.key + '-traefik', [self.runtime.host, '--configFile=' + str(self.runtime.artifacts.static_config)], self.host_env, self.runtime.handles)
            self.processes['traefik'] = (pre_host, str(self.runtime.host))
            self.runtime.helper.wait_for_port(self.runtime.host_port, pre_host, 'healthy host before sink constructor failure')
            self.result['readiness'] = http_readiness(self.case, self.runtime.host_port, self.runtime.env, self.runtime.lifecycle_path, base.actual_pid(pre_host, str(self.runtime.host)))
            self.result['startup_neighbor_before'] = command(self.key + '-startup-neighbor-before',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'neighbor-before'], self.runtime.env)
            base.snapshot(self.key + '-before-startup-fault', self.runtime.persistent | {'traefik': self.processes['traefik']})

    def start_engine(self):
        self.native = base.start(self.key + '-engine', [self.runtime.engine, '--serve', '--config', self.config, '--socket', self.engine_socket],
            self.engine_env, self.runtime.handles, (self.runtime.lifecycle_fd, self.fault_fd))
        self.processes['engine'] = (self.native, str(self.runtime.engine))
        try:
            self.runtime.helper.wait_for_socket(self.engine_socket, self.native, 'selected original-ID native engine')
            self.result['engine_started'] = True
        except Exception as error:
            self.result['engine_started'] = False
            self.result['engine_start_error'] = {'type': type(error).__name__, 'message': str(error)}
        self.fault_kind = (self.fixture.get('fault') or {}).get('kind')
        self.host_socket = self.engine_socket
        if self.result['engine_started'] and self.fault_kind in ('mse1-error', 'invalid-metadata', 'commit-ack-applied',
                'incomplete-framing', 'no-second-response', 'timeout', 'engine_timeout_before_commit', 'engine_timeout_after_commit'):
            self.host_socket = Path(PROXY_SOCKET)
            script = FIXTURES / 'acceptance_proxy.py'
            proxy = base.start(self.key + '-proxy', [PYTHON, '-P', script,
                self.host_socket, self.engine_socket, MANIFEST, self.key], self.runtime.env, self.runtime.handles)
            self.processes['proxy'] = (proxy, str(script))
            self.runtime.helper.wait_for_socket(self.host_socket, proxy, 'selected-operation actual MSE1 relay')
        elif self.fault_kind == 'uds-error':
            self.host_socket = Path(PROXY_SOCKET)
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            peer.bind(str(self.host_socket))
            self.proxy_identity = self.host_socket.lstat()
            peer.close()  # Physical socket entry, no listener: real ECONNREFUSED.

    def start_host(self):
        dynamic_config(self.runtime.helper, self.runtime.artifacts.dynamic_config, self.runtime.backend_port, self.host_socket, self.runtime.neighbor_socket, self.engine_socket, self.file_target)
        self.runtime.helper.write_static_config(self.runtime.artifacts.static_config, self.runtime.artifacts.dynamic_config, self.runtime.host_port, self.runtime.inputs.module_name)
        self.result['configuration'] = {str(p): base.digest(p) for p in (self.config, self.rules_path, self.runtime.artifacts.static_config, self.runtime.artifacts.dynamic_config)}
        self.result['native_log_start'] = self.runtime.lifecycle_path.stat().st_size
        self.result['host_log_start'] = self.runtime.host_path.stat().st_size
        if 'traefik' in self.processes:
            self.host_process = self.processes['traefik'][0]
        else:
            host_argv = [self.runtime.host, '--configFile=' + str(self.runtime.artifacts.static_config)]
            tracer = self.fixture.get('syscall_observer')
            if tracer:
                host_argv = [TASK / 'build/acceptance-syscalls', '--output', self.root / 'host-syscalls.jsonl',
                    '--nonce', tracer['nonce'], '--host-port', str(self.runtime.host_port), '--peer-port', '0',
                    '--seconds', str(tracer['seconds'])]
                self.result['syscall_observer'] = {'argv': list(map(str, host_argv)),
                    'source_sha256': base.digest(FIXTURES / 'acceptance_syscalls.c'),
                    'binary_sha256': base.digest(TASK / 'build/acceptance-syscalls'),
                    'qualification': None, 'missing_kernel_proof_is_unknown': True}
            self.host_process = base.start(self.key + '-traefik', host_argv, self.host_env, self.runtime.handles)
            self.processes['traefik'] = (self.host_process, str(self.runtime.host))
        self.runtime.helper.wait_for_port(self.runtime.host_port, self.host_process, 'actual pinned Traefik original-ID fixture')
        if 'readiness' not in self.result:
            self.result['readiness'] = http_readiness(self.case, self.runtime.host_port, self.runtime.env, self.runtime.lifecycle_path, base.actual_pid(self.host_process, str(self.runtime.host)))

    def before_controls(self):
        alive = self.runtime.persistent | {name: value for name, value in self.processes.items() if value[0].poll() is None}
        base.snapshot(self.key + '-before', alive)
        if self.result['engine_started']:
            self.result['main_engine_before'] = command(self.key + '-main-before',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'main-before'], self.runtime.env)
        if not self.result['engine_started'] and 'startup_neighbor_before' not in self.result:
            self.result['startup_neighbor_before'] = command(self.key + '-startup-neighbor-before',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'neighbor-before'], self.runtime.env)
        if self.fault_kind == 'commit-ack-applied':
            self.result['positive_ack_control'] = command(self.key + '-ack-control',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'ack-control'], self.runtime.env)

    def target_traffic(self):
        # Exercise independent traffic while the target's host/worker
        # operation is active, and retain same-engine controls separately.
        with ThreadPoolExecutor(max_workers=1) as executor:
            neighbor_future = executor.submit(command, self.key + '-neighbor',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'neighbor'], self.runtime.env)
            client_argv = [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key]
            if self.file_execution is not None and self.file_execution['supplement']['physical_reader'] == 'client':
                client_argv = file_process_argv(self.file_execution, 'client', self.runtime.host_port, self.case)
            client_env = self.file_execution['env'] if self.file_execution is not None and self.file_execution['supplement']['physical_reader'] == 'client' else self.runtime.env
            self.result['client'] = command(self.key + '-client', client_argv, client_env,
                timeout_seconds=self.fixture.get('target_timeout_seconds', 30))
            self.result['neighbor'] = neighbor_future.result()
        if self.fixture.get('sequence'):
            self.result['original_sequence'] = [command(self.key + '-sequence-' + str(index),
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'sequence-' + str(index)], self.runtime.env)
                for index in range(len(self.fixture['sequence']))]

        if self.result['engine_started'] and self.fixture.get('sink_recovery_control'):
            self.result['sink_recovery_control'] = command(self.key + '-sink-recovery',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'sink-recovery'], self.runtime.env)
        if self.result['engine_started']:
            self.result['main_engine_after'] = command(self.key + '-main-after',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'main-after'], self.runtime.env)
        if not self.result['engine_started']:
            self.result['startup_neighbor_after'] = command(self.key + '-startup-neighbor-after',
                [PYTHON, '-P', FIXTURES / CLIENT_SCRIPT, self.runtime.host_port, MANIFEST, self.key, 'neighbor-after'], self.runtime.env)

    def cleanup(self):
        for label in ('traefik', 'proxy', 'engine', 'file-backend'):
            if label in self.processes:
                try:
                    self.result['processes'][label] = stop(label, *self.processes[label])
                except Exception as error:
                    self.result.setdefault('cleanup_errors', []).append({'label': label, 'error': str(error)})
        if self.proxy_identity is not None:
            candidate = Path(PROXY_SOCKET)
            current = candidate.lstat()
            if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (self.proxy_identity.st_dev, self.proxy_identity.st_ino):
                candidate.unlink()
        self.result['socket_removed'] = not self.engine_socket.exists()
        self.result['socket_directory_cleanup'] = self.runtime.helper.remove_private_engine_socket_dir(self.socket_dir, self.runtime.inputs.engine_socket_parent)
        self.result['native_log_end'] = self.runtime.lifecycle_path.stat().st_size
        self.result['host_log_end'] = self.runtime.host_path.stat().st_size
        # Preserve each physical append-only segment before admitting
        # the next host process. Keep the original observer's1MiB cap.
        (self.root / HOST_LIFECYCLE).write_bytes(self.runtime.host_path.read_bytes())
        self.result['host_capture_sha256'] = base.digest(self.root / HOST_LIFECYCLE)
        self.runtime.host_path.write_bytes(b'')


def await_native_readiness(case, lifecycle_path, identity, offset, deadline, attempt, receipt):
    while time.monotonic() < deadline:
        counts = native_control_counts(lifecycle_path, identity, offset)
        attempt['native_counts'] = counts
        if (counts['native_allocations'] == 1 and counts['native_logging_returns'] == 1 and counts['native_logging_successes'] == 1 and
                counts['native_cleanup_returns'] == 1 and not counts['invalid_rows'] and not counts['malformed_rows'] and
                time.monotonic() <= deadline):
            receipt['ready'] = True
            base.write(case['key'] + READINESS_SUFFIX, receipt)
            return True
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.02, remaining))
    return False


def allocation_scope_status(allocation, returns):
    scope = allocation.get('allocation_scope_call')
    joined = [row for row in returns if row.get('allocation_scope_call') == scope]
    counts = {name: sum(row.get('function') == name for row in joined) for name in
        ('native_process_request_body', 'native_process_response_body', 'native_process_logging', 'native_cleanup')}
    successes = sum(row.get('function') == 'native_process_logging' and row.get('result') == 1 for row in joined)
    done = bool(scope) and all(count == 1 for count in counts.values()) and successes == 1
    return {'allocation_scope_call': scope, 'transaction_id': allocation.get('transaction_id'),
        'native_returns': counts, 'native_logging_successes': successes, 'complete': done}

def strict_capability_probe(helper, inputs, engine, neighbor_config, native_env, lifecycle_fd):
    # Parser acceptance and profile startup admission are different claims.
    # Native Strict capability is rejected by profile binding, not necessarily
    # by the generic configuration parser. No traffic/lifecycle is invented.
    strict_dir = helper.create_private_engine_socket_dir(inputs.engine_socket_parent)
    strict_config = TASK / 'strict-capability.conf'
    strict_config.write_text(strict_configuration(neighbor_config.read_text()))
    strict_receipt = {'route': 'traefik-native-uds', 'configuration_sha256': base.digest(strict_config),
        'native_transactions_claimed': False, 'qualification': None}
    try:
        strict_env = native_env | {'MSCONNECTOR_LIFECYCLE_CASE': 'supplementary-native-strict-startup'}
        strict_receipt['parser'] = command('strict-capability-configtest',
            [engine, '--check-config', '--config', strict_config], strict_env, (lifecycle_fd,))
        strict_receipt['startup'] = command('strict-capability-startup',
            [engine, '--serve', '--config', strict_config, '--socket', strict_dir.path / helper.ENGINE_SOCKET_FILENAME],
            strict_env, (lifecycle_fd,))
    except Exception as error:
        strict_receipt['execution_error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        strict_receipt['socket_removed'] = not (strict_dir.path / helper.ENGINE_SOCKET_FILENAME).exists()
        strict_receipt['socket_directory_cleanup'] = helper.remove_private_engine_socket_dir(strict_dir, inputs.engine_socket_parent)
        base.write('strict-capability.json', strict_receipt)


def cleanup_runtime(helper, inputs, handles, persistent, neighbor, lifecycle_fd, lifecycle_path):
    neighbor_batch, neighbor_socket, neighbor_dir = neighbor
    cleanup = {}
    for label in ('neighbor-engine', 'backend'):
        if label in persistent:
            try:
                cleanup[label] = stop(label, *persistent[label])
            except Exception as error:
                cleanup[label] = {'cleanup_error': {'type': type(error).__name__, 'message': str(error)}}
    if neighbor_batch is not None:
        native = neighbor_scope_status(lifecycle_path, neighbor_batch, final=True)
        cleanup['neighbor_native_final'] = native
        base.write('neighbor-batch-' + str(neighbor_batch['batch_index']) + '-final.json', {
            'batch': neighbor_batch, 'process': cleanup.get('neighbor-engine'), 'native': native,
            'socket_removed': not neighbor_socket.exists()})
    os.close(lifecycle_fd)
    for handle in handles:
        handle.close()
    cleanup['neighbor_socket_removed'] = not neighbor_socket.exists()
    cleanup['neighbor_socket_directory_cleanup'] = helper.remove_private_engine_socket_dir(neighbor_dir, inputs.engine_socket_parent)
    return cleanup


def selected_executions(manifest):
    executions = manifest['cases'] + manifest.get('supplementary_executions', [])
    selected = manifest.get('selected_keys')
    if selected is not None:
        known = {case['key'] for case in executions}
        if not isinstance(selected, list) or len(set(selected)) != len(selected) or not set(selected) <= known:
            raise ValueError('Invalid original-case execution filter')
        executions = [case for case in executions if case['key'] in selected]
    return executions


def run(helper, inputs, artifacts, engine, host, env):
    manifest = json.loads(MANIFEST.read_text())
    (TASK / 'cases').mkdir(mode=0o700)
    handles, persistent = [], {}
    all_results = []
    backend_port, host_port = helper.free_port(), helper.free_port()
    lifecycle_path = artifacts.logs_dir / 'native-lifecycle.jsonl'
    host_path = artifacts.logs_dir / HOST_LIFECYCLE
    for path in (lifecycle_path, host_path):
        path.touch(mode=0o600, exist_ok=True)
    lifecycle_fd = os.open(lifecycle_path, os.O_WRONLY | os.O_APPEND)
    neighbor_dir = helper.create_private_engine_socket_dir(inputs.engine_socket_parent)
    neighbor_socket = neighbor_dir.path / helper.ENGINE_SOCKET_FILENAME
    neighbor_config = TASK / 'neighbor.conf'
    neighbor_rules = TASK / 'neighbor-rules.conf'
    neighbor_rules.write_text('SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\n')
    helper.write_engine_config(neighbor_config, neighbor_rules, TASK / 'neighbor-events.jsonl')
    native_env = env | {'MSCONNECTOR_LIFECYCLE_FD': str(lifecycle_fd),
        'MSCONNECTOR_LIFECYCLE_RUN': 'tf-i12-acceptance-native-20261015',
        'MSCONNECTOR_LIFECYCLE_PROFILE': 'traefik-native-uds'}
    neighbor_batch, neighbor_uses = None, 0

    def start_neighbor_batch(index):
        offset = lifecycle_path.stat().st_size
        process = base.start('neighbor-engine-batch-' + str(index),
            [engine, '--serve', '--config', neighbor_config, '--socket', neighbor_socket],
            native_env | {'MSCONNECTOR_LIFECYCLE_CASE': 'independent-neighbor-control-batch-' + str(index)}, handles, (lifecycle_fd,))
        persistent['neighbor-engine'] = (process, str(engine))
        helper.wait_for_socket(neighbor_socket, process, 'independent healthy native engine')
        return {'batch_index': index, 'pid': base.actual_pid(process, str(engine)), 'native_log_start': offset,
            'configuration_sha256': base.digest(neighbor_config), 'batch_size': NEIGHBOR_BATCH_SIZE}

    def stop_neighbor_batch():
        return stop('neighbor-engine', *persistent['neighbor-engine'])

    runtime = None
    try:
        strict_capability_probe(helper, inputs, engine, neighbor_config, native_env, lifecycle_fd)
        backend_script = FIXTURES / 'acceptance_backend.py'
        backend = base.start('backend', [PYTHON, '-P', backend_script, backend_port, MANIFEST], env, handles)
        persistent['backend'] = (backend, str(backend_script))
        helper.wait_for_port(backend_port, backend, 'independent early-entry backend')
        executions = selected_executions(manifest)
        runtime = SimpleNamespace(helper=helper, inputs=inputs, artifacts=artifacts,
            engine=engine, host=host, env=env, native_env=native_env,
            lifecycle_path=lifecycle_path, host_path=host_path, lifecycle_fd=lifecycle_fd,
            backend_port=backend_port, host_port=host_port, neighbor_socket=neighbor_socket,
            handles=handles, persistent=persistent, neighbor_batch=neighbor_batch,
            neighbor_uses=neighbor_uses, stop_neighbor_batch=stop_neighbor_batch,
            start_neighbor_batch=start_neighbor_batch)
        for case in executions:
            all_results.append(CaseExecution(case, runtime).execute())
            neighbor_batch = runtime.neighbor_batch

    finally:
        if runtime is not None:
            neighbor_batch = runtime.neighbor_batch
        cleanup = cleanup_runtime(helper, inputs, handles, persistent,
            (neighbor_batch, neighbor_socket, neighbor_dir), lifecycle_fd, lifecycle_path)
        base.write('acceptance-result.json', {'route': 'traefik-native-uds', 'qualification': None,
            'original_ids_planned': 118, 'original_ids_attempted': len({row['id'] for row in all_results}),
            'executions_attempted': len(all_results), 'selected_keys': manifest.get('selected_keys'),
            'results': all_results, 'cleanup': cleanup})
