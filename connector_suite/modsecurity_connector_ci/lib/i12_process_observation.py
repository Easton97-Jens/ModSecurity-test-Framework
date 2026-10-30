"""Maintained process observations for controls formerly loading archived drivers."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from modsecurity_connector_ci.lib.i12_path_safety import create_text, leaf_name, output_path
from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root


def descendants(process):
    queue, result = [process.pid], []
    while queue:
        pid = queue.pop()
        result.append(pid)
        try:
            child_text = Path(f'/proc/{pid}/task/{pid}/children').read_text()
        except FileNotFoundError:
            continue
        queue.extend(int(value) for value in child_text.split())
        if len(result) > 128:
            raise RuntimeError('bounded task process inventory exceeded')
    return result


def actual_pid(process, marker):
    found = []
    for pid in descendants(process):
        try:
            arguments = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        except FileNotFoundError:
            continue
        direct_binary = arguments[0] == marker.encode()
        direct_python = arguments[:3] == [b'/usr/local/bin/python3', b'-P', marker.encode()]
        if direct_binary or direct_python:
            found.append(pid)
    if len(found) != 1:
        raise RuntimeError(f'exact process identity unavailable for {marker}: {found}')
    return found[0]


def _descriptor_inventory(base):
    descriptors, vanished = {}, []
    for descriptor in sorted(base.joinpath('fd').iterdir(), key=lambda item: int(item.name)):
        try:
            descriptors[descriptor.name] = os.readlink(descriptor)
        except FileNotFoundError:
            vanished.append(descriptor.name)
    return descriptors, vanished


def _identity_fields(status):
    return {key: next((line.split(':', 1)[1].strip() for line in status.splitlines()
                       if line.startswith(key + ':')), None)
            for key in ('Uid', 'Gid', 'CapEff', 'CapBnd', 'NoNewPrivs')}


class ProcessObservation:
    """Observe explicitly supplied child processes and publish private snapshots."""

    actual_pid = staticmethod(actual_pid)
    descendants = staticmethod(descendants)

    def __init__(self, root, *, sdk_sha=None, writer=None):
        self.TASK = Path(root)
        self.SOURCE = connector_root()
        self.sdk_sha = sdk_sha
        self._writer = writer

    @staticmethod
    def digest(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def write(self, name, value):
        name = leaf_name(name)
        if self._writer is not None:
            self._writer(name, value)
        else:
            create_text(self.TASK / name, json.dumps(value, indent=2) + '\n')

    def _launch_stream(self, name):
        name = leaf_name(name)
        output_path(self.TASK / name)
        with open_private_runtime_root(self.TASK) as root:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=root.descriptor)
        return os.fdopen(descriptor, 'wb')

    def start(self, label, argv, environment, handles, pass_fds=()):
        label = leaf_name(label)
        stdout = self._launch_stream(f'{label}.stdout')
        handles.append(stdout)
        stderr = self._launch_stream(f'{label}.stderr')
        handles.append(stderr)
        command = ['rtk', 'proxy', *map(str, argv)]
        process = subprocess.Popen(command, cwd=self.TASK / 'runtime', env=environment,
                                   stdout=stdout, stderr=stderr, pass_fds=pass_fds)
        self.write(f'{label}.launch.json', {'argv': command, 'proxy_pid': process.pid,
                                          'monotonic_ns': time.monotonic_ns()})
        return process

    def _process_record(self, label, name, process, marker):
        pid = self.actual_pid(process, marker)
        base = Path(f'/proc/{pid}')
        status = base.joinpath('status').read_text()
        maps = base.joinpath('maps').read_text()
        create_text(self.TASK / f'{label}.{name}.maps.raw', maps)
        create_text(self.TASK / f'{label}.{name}.status.raw', status)
        descriptors, vanished = _descriptor_inventory(base)
        libraries = sorted({line.split()[-1] for line in maps.splitlines()
                            if 'libmodsecurity.so' in line and line.split()[-1].startswith('/')})
        record = {'pid': pid, 'proxy_pid': process.pid, 'executable': os.readlink(base / 'exe'),
                  'executable_sha256': self.digest(base / 'exe'), 'fd_count': len(descriptors),
                  'fds': descriptors, 'vanished_during_snapshot': vanished,
                  'native_libraries': [{'path': item, 'sha256': self.digest(item)} for item in libraries],
                  'identity': _identity_fields(status)}
        if name == 'engine' and (len(libraries) != 1 or self.sdk_sha is None
                                or record['native_libraries'][0]['sha256'] != self.sdk_sha):
            raise RuntimeError('actual engine mapping does not bind the selected SDK')
        return record

    def snapshot(self, label, processes):
        label = leaf_name(label)
        value = {'monotonic_ns': time.monotonic_ns(), 'wall_ns': time.time_ns(), 'processes': {}}
        value['clock_calibration'] = {'wall_before_ns': time.time_ns(),
                                      'monotonic_ns': time.monotonic_ns(), 'wall_after_ns': time.time_ns()}
        for name, (process, marker) in processes.items():
            name = leaf_name(name)
            value['processes'][name] = self._process_record(label, name, process, marker)
        for name in ('tcp', 'tcp6', 'unix'):
            create_text(self.TASK / f'{label}.net-{name}.raw', Path(f'/proc/net/{name}').read_text())
        self.write(f'{label}.json', value)
