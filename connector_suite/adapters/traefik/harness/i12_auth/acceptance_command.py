"""Bounded task-owned client waits; retain timeouts and reap the exact group."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def validate_command(root, label, argv, seconds):
    if root.parent != Path('/task/cases') or root.resolve(strict=True) != root:
        raise ValueError('fixed private case required')
    if not ((label == 'client-target' and seconds == 120) or
            (re.fullmatch(r'readiness-\d', label, flags=re.ASCII) and 0 < seconds <= 3)):
        raise ValueError('only fixed target/readiness deadlines allowed')
    expected = ['/usr/local/bin/python3', '-P', '/mnt/fixtures/acceptance_net.py', 'client',
                '--spec', str(root / 'case.json'), '--root', str(root), '--port']
    actual = list(map(str, argv))
    if actual[:9] != expected or len(actual) < 10 or not 1 <= int(actual[9]) <= 65535:
        raise ValueError('fixed loopback client argv required')
    if label.startswith('readiness-'):
        if actual[10:] != ['--neighbor', '--readiness-index', label[-1]]:
            raise ValueError('fixed readiness identity required')
    elif actual[10:]:
        raise ValueError('fixed target client required')
    return ['rtk', 'proxy', *actual]


def wait_process(process, command, deadline, seconds):
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, seconds)
        process.wait(timeout=remaining)
        return False, None
    except subprocess.TimeoutExpired:
        reap_started = time.monotonic_ns()
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        return True, reap_started


def execute(root, label, argv, env, seconds, absolute_deadline=None):
    command = validate_command(root, label, argv, seconds)
    started = time.monotonic_ns()
    deadline = time.monotonic() + seconds
    if absolute_deadline is not None:
        if not label.startswith('readiness-'):raise ValueError('absolute deadline only for readiness')
        deadline = min(deadline, absolute_deadline)
    timed_out = False
    reap_started = None
    with (root / (label + '.stdout')).open('xb') as stdout, (root / (label + '.stderr')).open('xb') as stderr:
        process = subprocess.Popen(command, cwd='/mnt/src', env=env, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        timed_out, reap_started = wait_process(process, command, deadline, seconds)
    result = {'argv': command, 'cwd': '/mnt/src', 'wrapper_pid': process.pid,
              'started_ns': started, 'completed_ns': time.monotonic_ns(),
              'exit_code': process.returncode, 'signal': -process.returncode if process.returncode < 0 else 0,
              'timed_out': timed_out, 'deadline_seconds': seconds, 'qualification': None,
              'reap_started_ns': reap_started,
              'reap_completed_ns': time.monotonic_ns() if reap_started is not None else None,
              'reap_deadline_seconds': 6 if reap_started is not None else None,
              'stdout_sha256': hashlib.sha256((root / (label + '.stdout')).read_bytes()).hexdigest(),
              'stderr_sha256': hashlib.sha256((root / (label + '.stderr')).read_bytes()).hexdigest()}
    (root / (label + '.command.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result
