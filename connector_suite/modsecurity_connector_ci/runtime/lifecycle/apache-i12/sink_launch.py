#!/usr/bin/env python3
"""Native Apache sink extension of the existing direct and lifecycle runners.

Original direct-runner helpers and raw lifecycle client are sealed fixtures.
No observer, product source, runtime admission, or fault return is replaced.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

paths = load_tool('ci/runtime/lifecycle/apache-i12/paths.py')
capture_process = load_tool('ci/runtime/lifecycle/apache-i12/process_capture.py').capture_process
import shutil
import subprocess
import sys
import threading
import time

direct = load_source('/mnt/fixtures/direct-runner.py')
settings = json.loads(Path('/mnt/fixtures/sink-settings.json').read_text())
admission = json.loads(Path('/opt/controller/admission.json').read_text())
binding = dict(settings['binding'], outside_namespaces=admission['outside_namespaces'])
current = direct.admission(binding)
os.environ['CODEX_TEMP_ROOT'] = settings['storage_root']
base = paths.private_directory(settings['runtime_root'])
owned = base / 'native-bin/apache2'
owned.parent.mkdir(mode=0o700)
shutil.copyfile('/usr/sbin/apache2', owned)
owned.chmod(0o500)
assert direct.sha(owned) == binding['input_sha256']['/usr/sbin/apache2']
direct.save('/task/sink-admission.json', current)
backend_root = base / 'backend'
backend_root.mkdir(mode=0o700)
backend_port = direct.free_port()
backend_stop_receipt = None


def cleanup_backend():
    global backend_stop_receipt
    if backend_stop_receipt is None:
        backend_stop_receipt = direct.stop(backend, backend_port, backend_root / 'cleanup.json')
    return backend_stop_receipt


with ExitStack() as cleanup:
    backend, backend_command = direct.launch([sys.executable, '/mnt/fixtures/direct-runner.py',
        '--backend', '--backend-dir', str(backend_root), '--port', str(backend_port)],
        backend_root, backend_root / 'process')
    cleanup.callback(cleanup_backend)
    direct.save(backend_root / 'launch.json', backend_command)
    case = settings['case']
    root = base / case['name']
    root.mkdir(mode=0o700)
    event = root / 'events.jsonl'
    event.touch(mode=0o600)
    marker = root / 'sink-fault.marker'
    marker.write_text('I12_APACHE_SINK_FAULT_V1\n')
    marker.chmod(0o600)
    sink = str(event)
    if case['fault'] == 'badpath':
        sink = str(root / 'missing/events.jsonl')
    elif case['fault'] == 'devfull':
        sink = '/dev/full'
    elif case['fault'] == 'unwritable':
        denied = root / 'unwritable'
        denied.mkdir(mode=0o500)
        sink = str(denied / 'events.jsonl')
    port = direct.free_port()
    config = root / 'httpd.conf'
    config.write_text(direct.config_text(case, root, port, backend_port, sink).replace(
        '/mnt/artifacts/apache/module.so', '/mnt/artifacts/apache/test-observed.so'))
    config.chmod(0o600)
    env = dict(os.environ,
        LD_PRELOAD='/mnt/artifacts/apache/apr-sink-fault.so',
        I12_SINK_ROOT=str(base), I12_SINK_PATH=sink, I12_SINK_MARKER=str(marker),
        I12_SINK_FAULT=case['fault'] if case['fault'] in ('closed-descriptor', 'physical-enospc') else 'observe',
        MSCONNECTOR_APACHE_NATIVE_OBSERVER='/task/apache-native-api.jsonl',
        MSCONNECTOR_APACHE_HOST_OBSERVER='/task/apache-host-eos.jsonl',
        MSCONNECTOR_APACHE_BACKEND_CAPTURE='/task/apache-backend.jsonl',
        MSCONNECTOR_LIFECYCLE_RUN=settings['run_id'],
        MSCONNECTOR_LIFECYCLE_PROFILE='apache-native',
        MSCONNECTOR_LIFECYCLE_CASE=case['case_id'])
    stop_sampler = threading.Event()
    snapshots = []
    sampler_errors = []
    host = None
    observed = {'settings': settings, 'sink': sink, 'config_sha256': direct.sha(config),
        'actual_runtime': None, 'full_lifecycle_qualification': None, 'clients': [],
        'apr_open_result': None, 'missing_observations': []}


    def sample(pid):
        while not stop_sampler.is_set():
            for child in direct.descendant_pids(pid):
                try:
                    proc = Path('/proc') / str(child)
                    if os.readlink(proc / 'exe') != str(owned):
                        continue
                    snapshots.append(capture_process(child))
                except (FileNotFoundError, ProcessLookupError):
                    pass
                except Exception as error:
                    sampler_errors.append({'type': type(error).__name__, 'message': str(error)})
            stop_sampler.wait(.05)


    def client(label):
        uri = '/sink-disruptive' if label == 'main' else '/' + label
        token = str(time.time_ns())
        request_id = settings['run_id'] + '-' + label
        output = Path('/task/client')
        output.mkdir(mode=0o700, exist_ok=True)
        argv = [sys.executable, '/mnt/fixtures/curl-raw-client.py', '-sS', '--http1.1',
            '-D', str(output / (label + '.headers')), '-X', 'GET',
            '-o', str(output / (label + '.body')), '-w', '%{http_code}',
            '-H', 'X-I12-ID: ' + request_id,
            'http://127.0.0.1:' + str(port) + uri]
        receipt = direct.waited(argv, root, root / label,
            dict(os.environ, I12_APACHE_CLIENT_TOKEN=token), timeout=25)
        receipt.update(role=label, request_id=request_id, client_token=token, uri=uri,
            actual_waited_exit_code=receipt['waited_exit'],
            stdout_bytes=(root / (label + '.stdout')).stat().st_size,
            stderr_bytes=(root / (label + '.stderr')).stat().st_size)
        direct.save(output / (token + '.actual-process.json'), receipt)
        return receipt


    thread = None
    try:
        direct.ready(backend, backend_port, os.path.realpath(sys.executable))
        for flag in ('-t', '-M'):
            command = direct.waited([str(owned), flag, '-f', str(config)], root,
                root / ('configtest' if flag == '-t' else 'modules'), env)
            if command['waited_exit'] != 0:
                raise RuntimeError('actual configuration/module check failed')
        host, observed['launch'] = direct.launch([str(owned), '-X', '-f', str(config)], root, root / 'host', env)
        thread = threading.Thread(target=sample, args=(host.pid,), daemon=True)
        thread.start()
        observed['host_identity'] = direct.ready(host, port, str(owned))
        time.sleep(.2)
        for label in ('main', 'followup', 'neighbor'):
            observed['clients'].append(client(label))
            time.sleep(.2)
    except Exception as error:
        observed['setup_or_execution_error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        stop_sampler.set()
        if thread is not None:
            thread.join(timeout=5)
        try:
            if host is not None:
                observed['host_cleanup'] = direct.stop(host, port, root / 'host-cleanup.json')
        finally:
            observed['backend_cleanup'] = cleanup_backend()
            observed.update(native_process_snapshots=snapshots, native_process_sampler_errors=sampler_errors,
                sampler_thread_stopped=thread is None or not thread.is_alive(),
                physical_event_sha256=direct.sha(event), backend_log_path=str(backend_root / 'requests.jsonl'),
                full_lifecycle_qualification=None)
            direct.save('/task/sink-observation.json', observed)
    print(json.dumps({'case': case['name'], 'actual_clients': len(observed['clients']),
        'sampler_snapshots': len(snapshots), 'full_lifecycle_qualification': None}))
    raise SystemExit(1 if 'setup_or_execution_error' in observed else 0)
