"""Signal and reap only this fixed controller's actual client child."""
from modsecurity_test_framework.connector_context import load_source
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import time

def validate_case(root, port):
    if (os.geteuid(), os.getegid()) != (65534, 65534) or root.parent != Path('/task/cases'):
        raise RuntimeError('admitted private case required')
    if not re.fullmatch(r'ac-[0-9a-f]{20}', root.name) or root.resolve(strict=True) != root or not 1 <= port <= 65535:
        raise ValueError('fixed original client case and loopback port required')
    case = json.loads((root / 'case.json').read_text())
    if case['probe_id'] != root.name or case['case_id'] != 'NEED-client-exit-signal':
        raise ValueError('original signal case required')
    return case


def client_arguments(root, port):
    validate_case(root, port)
    return ['/usr/local/bin/python3', '-P', '/mnt/fixtures/acceptance_net.py', 'client',
            '--spec', str(root / 'case.json'), '--root', str(root), '--port', str(port)]


def start_client(root, port):
    argv = client_arguments(root, port)
    pid = os.fork()
    if pid == 0:
        try:
            os.chdir(root / 'runtime')
            os.execve('/usr/local/bin/python3', argv, os.environ.copy())
        except OSError:
            os._exit(127)
    return pid


def await_progress(root, pid):
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        path = root / 'client-signal-ready.json'
        if path.is_file():
            try:
                value = json.loads(path.read_text())
            except json.JSONDecodeError:
                time.sleep(0.01)
                continue
            if value.get('pid') == pid and value.get('entity_bytes_received', 0) >= 8192:
                return value, None
        reaped, status = os.waitpid(pid, os.WNOHANG)
        if reaped == pid:
            return None, status
        time.sleep(0.01)
    return None, None


def execute(root, port):
    case = validate_case(root, port)
    parser_helpers = load_source('/mnt/fixtures/acceptance_parser.py')
    argv = client_arguments(root, port)
    started = time.monotonic_ns()
    pid = start_client(root, port)
    progress, already_reaped = await_progress(root, pid)
    sent = None
    if already_reaped is not None:
        status, timeout = already_reaped, False
    else:
        sent = time.monotonic_ns()
        os.kill(pid, signal.SIGTERM if progress else signal.SIGKILL)
        status, timeout = parser_helpers.wait_child(pid, 2)
    completed = time.monotonic_ns()
    requested_signal = None
    if sent:
        requested_signal = signal.SIGTERM if progress else signal.SIGKILL
    result = {'probe': case['probe_id'], 'pid': pid, 'controller_pid': os.getpid(),
              'argv': argv, 'cwd': str(root / 'runtime'), 'uid': os.geteuid(),
              'monotonic_ns': started, 'completed_ns': completed,
              'actual_client_progress': progress, 'signal_sent_monotonic_ns': sent,
              'requested_signal': requested_signal,
              **parser_helpers.decode_wait(status), 'cleanup_timeout': timeout,
              'client_executable_sha256': hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest(),
              'client_script_sha256': hashlib.sha256(Path(argv[2]).read_bytes()).hexdigest(),
              'observations_only': True, 'qualification': None}
    (root / 'client-signal-controller.json').write_text(json.dumps(result, indent=2) + '\n')
    (root / 'client-target.command.json').write_text(json.dumps(result, indent=2) + '\n')
    (root / 'client-target.json').write_text(json.dumps({
        'probe': case['probe_id'], 'pid': pid, 'monotonic_ns': started, 'completed_ns': completed,
        'requests': [progress] if progress else [], 'observations_only': True,
        'terminated_by_waited_signal': result['signal'], 'client_normal_completion': False,
        'physical_wait_receipt': 'client-signal-controller.json'}, indent=2) + '\n')
    (root / 'client-signal-reaped').write_text(str(completed))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    measured = execute(args.case_root, args.port)
    print(json.dumps({'pid': measured['pid'], 'exit_code': measured['exit_code'],
                      'signal': measured['signal'], 'qualification': None}))
