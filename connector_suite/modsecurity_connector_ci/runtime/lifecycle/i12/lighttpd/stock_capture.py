#!/usr/bin/env python3
"""Bounded, source-bound stock-sidecar supplement; never promotes I12 oracles.

The exported I12 lighttpd collector is linked only into a disposable external
source copy. Root observations remain explicitly separate from nonroot evidence.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
try:
    from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.qualification import EXTERNAL_ROOT, storage_root
except ModuleNotFoundError:
    from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.qualification import EXTERNAL_ROOT, storage_root

REPO = next((parent for parent in Path(__file__).resolve().parents
             if (parent / 'ci/runtime/lifecycle/i12/manifest.json').is_file()), Path('/mnt/src'))
EXTERNAL = EXTERNAL_ROOT
PROFILES = ('off', 'safe', 'strict', 'all')
BACKEND_LOG = 'backend.jsonl'
EVENT_LOG = 'events.jsonl'
BODY_PATH = '/body.txt'
EMPTY_PATH = '/empty.txt'


def sha(path):
    resolved = Path(path).resolve(strict=True)
    if resolved.is_relative_to(EXTERNAL):
        storage_root(EXTERNAL)
    allowed = (EXTERNAL, REPO, Path('/usr/lib/x86_64-linux-gnu'))
    if not any(resolved.is_relative_to(root) for root in allowed):
        raise ValueError('hash input outside declared capture/source/library roots')
    return hashlib.sha256(resolved.read_bytes()).hexdigest()


def regular(path):
    path = Path(path)
    if any(parent.is_symlink() for parent in (*path.parents, path)):
        raise ValueError('symlink in source input')
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise ValueError('source input must be regular and have one link')
    return path


def copy_tree(source, target):
    if any(parent.is_symlink() for parent in (*source.parents, source)):
        raise ValueError('symlink in source directory')
    target.mkdir(mode=0o700, parents=True)
    for path in source.rglob('*'):
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            raise ValueError('symlink in source tree')
        destination = target / path.relative_to(source)
        if path.is_dir():
            destination.mkdir(mode=0o700, exist_ok=True)
        else:
            shutil.copyfile(regular(path), destination)


def private_root(path):
    storage_root(EXTERNAL)
    """Reject aliases and permissive roots, including links in any ancestor."""
    path = Path(path).absolute()
    if '..' in path.parts or not path.is_relative_to(EXTERNAL):
        raise ValueError('capture must reside below the external task root')
    for ancestor in (*reversed(path.parents), path):
        if ancestor.is_symlink():
            raise ValueError('symlink in capture path')
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('capture root is not private')
    return path


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    path.chmod(0o600)


def run(root, label, argv, timeout=120):
    command = ['rtk', 'proxy', *map(str, argv)]
    result = subprocess.run(command, capture_output=True, timeout=timeout)
    (root / (label + '.stdout')).write_bytes(result.stdout)
    (root / (label + '.stderr')).write_bytes(result.stderr)
    write(root / (label + '.command.json'), {'argv': command, 'exit': result.returncode})
    if result.returncode:
        raise RuntimeError(label + ': ' + result.stderr.decode(errors='replace')[-3000:])
    return result


def prepare(root):
    source = root / 'source'
    source.mkdir(mode=0o700)
    for relative in ('common', 'connectors/lighttpd'):
        copy_tree(REPO / relative, source / relative)
    for relative in ('connectors/profile_registry.c', 'connectors/profile_registry.h',
                     'ci/runtime/lifecycle/native-lifecycle-observer.c',
                     'ci/runtime/lifecycle/native-lifecycle-observer.h',
                     'ci/runtime/lifecycle/native-lifecycle-sdk.cpp'):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(regular(REPO / relative), target)
    write(source / '.i12-disposable-source-copy.json', {
        'format': 'i12-disposable-source-copy-v1', 'path': str(source),
        'disposable': True, 'parent_sha': '8cc32dceb06121f589150a9794f28878c5e4ba2a'})
    run(root, 'capture-export', ['python3', '-B', REPO / 'ci/runtime/lifecycle/i12/capture_sources.py',
                               'apply', '--profile', 'lighttpd', '--source-copy', source])
    helper = source / 'lighttpd-host-observer.c'
    original = helper.read_text()
    prefix = str(root) + '/'
    needle = 'strncmp(path,"/task/",6U)==0'
    if original.count(needle) != 1:
        raise RuntimeError('unexpected original host-observer prefix guard')
    relocated = original.replace(needle, f'strncmp(path,"{prefix}",sizeof("{prefix}")-1U)==0')
    binding = {'original_sha256': sha(helper), 'exact_original_guard': needle,
               'relocated_prefix': prefix, 'file_owner_mode_nofollow_checks_retained': True}
    helper.write_text(relocated)
    binding['relocated_sha256'] = sha(helper)
    write(root / 'host-observer-relocation.json', binding)
    build = root / 'build'
    build.mkdir(mode=0o700)
    strict = ['-Wall', '-Wextra', '-Werror', '-fPIC', '-fno-lto', '-pthread']
    includes = ['-I', source, '-I', source / 'common/include', '-I', source / 'common/runtime',
                '-I', source / 'ci/runtime/lifecycle', '-I', source / 'connectors/lighttpd/stock_sidecar']
    objects = []
    for name, relative in (
        ('observer', 'ci/runtime/lifecycle/native-lifecycle-observer.c'),
        ('host', 'lighttpd-host-observer.c'), ('bootstrap', 'lighttpd-observer-fd-bootstrap.c'),
        ('sdk', 'ci/runtime/lifecycle/native-lifecycle-sdk.cpp')):
        target = build / (name + '.o')
        cxx = name == 'sdk'
        run(root, 'compile-' + name, ['g++' if cxx else 'cc', '-std=c++17' if cxx else '-std=c17',
                                    *strict, *includes, '-c', source / relative, '-o', target])
        objects.append(target)
    symbols_result = run(root, 'wrapped-symbols', ['nm', '-g', build / 'observer.o'])
    symbols = sorted({line.split()[-1][7:] for line in symbols_result.stdout.decode().splitlines()
                      if line.split() and line.split()[-1].startswith('__wrap_')})
    binary = build / 'lighttpd-stock-sidecar'
    run(root, 'compile-sidecar', ['cc', '-std=c17', *strict, *includes,
        '-DMSCONNECTOR_STOCK_SIDECAR_MAIN', source / 'connectors/lighttpd/stock_sidecar/stock_sidecar.c',
        source / 'common/runtime/msconnector_runtime.c', source / 'connectors/profile_registry.c',
        *sorted((source / 'common/src').glob('*.c')), *objects,
        *['-Wl,--wrap=' + name for name in symbols], '-lstdc++', '-lmodsecurity', '-lcrypto', '-lyajl',
        '-o', binary])
    write(root / 'build-binding.json', {'binary_sha256': sha(binary), 'wrapped_symbols': symbols,
        'capture_application_receipt_sha256': sha(source / 'i12-source-application-receipt.json'),
        'source_inputs': {str(p.relative_to(source)): sha(p) for p in source.rglob('*') if p.is_file()},
        'sdk_image_sha256': sha('/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14'),
        'qualification': None})
    return binary


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def request(port, target, body=b'', reset=False, hold=None, content_type='text/plain'):
    result = {'request_body_bytes': len(body), 'reset_requested': reset}
    payload = (f'POST {target} HTTP/1.1\r\nHost: stock.test\r\nContent-Type: {content_type}\r\n'
               f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body
    received = bytearray()
    with socket.create_connection(('127.0.0.1', port), timeout=4) as stream:
        stream.settimeout(5)
        if hold is None:
            stream.sendall(payload)
        else:
            boundary = len(payload) - len(body) + min(1024, len(body))
            stream.sendall(payload[:boundary])
            time.sleep(.08)
            hold()
            stream.sendall(payload[boundary:])
        if reset:
            import struct
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        else:
            try:
                while chunk := stream.recv(16384):
                    received.extend(chunk)
                    if len(received) > 131072:
                        raise RuntimeError('bounded client response exceeded')
                result['peer_eof_seen'] = True
            except OSError as error:
                result['transport_error'] = repr(error)
    result['request_sha256'] = hashlib.sha256(payload).hexdigest()
    result['response_sha256'] = hashlib.sha256(received).hexdigest()
    result['response_bytes'] = len(received)
    result['status_line'] = bytes(received).split(b'\r\n', 1)[0].decode(errors='replace')
    result['response_body'] = bytes(received).partition(b'\r\n\r\n')[2].decode(errors='replace')
    return result


def launch(root, name, argv, env):
    stdout = (root / (name + '.stdout')).open('xb')
    try:
        stderr = (root / (name + '.stderr')).open('xb')
        try:
            command = ['rtk', 'proxy', *map(str, argv)]
            child = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
        except BaseException:
            stderr.close()
            raise
    except BaseException:
        stdout.close()
        raise
    return child, stdout, stderr, command


def ready(port, process):
    # Inspect LISTEN state: readiness must not create an empty engine transaction.
    for _ in range(150):
        if process.poll() is not None:
            raise RuntimeError('process exited before LISTEN: ' + str(process.returncode))
        rows = Path('/proc/net/tcp').read_text().splitlines()[1:]
        if any(row.split()[3] == '0A' and row.split()[1].endswith(f':{port:04X}') for row in rows):
            return
        time.sleep(.02)
    raise RuntimeError('LISTEN timeout')


def process_inventory():
    processes = {}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            processes[int(path.name)] = (int(fields[1]), fields[19])
        except (OSError, IndexError):
            continue
    return processes


def is_descendant(pid, launcher, processes):
    visited = set()
    while pid in processes and pid not in visited:
        if pid == launcher:
            return True
        visited.add(pid)
        pid = processes[pid][0]
    return False


def native_process_snapshot(pid, token, binary):
    proc = Path('/proc', str(pid))
    if (proc / 'exe').resolve() != binary.resolve():
        return None
    fds = []
    for fd in (proc / 'fd').iterdir():
        detail = fd.stat()
        fds.append({'fd': fd.name, 'target': os.readlink(fd),
                    'mode': oct(stat.S_IMODE(detail.st_mode)), 'uid': detail.st_uid,
                    'size': detail.st_size, 'links': detail.st_nlink})
    return {'pid': pid, 'starttime': token, 'exe_sha256': sha(proc / 'exe'),
            'maps': (proc / 'maps').read_text(), 'status': (proc / 'status').read_text(), 'fds': fds}


def process_snapshot(launcher, binary):
    """Bind the real native descendant and inspect live unlinked spool FDs."""
    processes = process_inventory()
    observations = []
    for pid, (_parent, token) in processes.items():
        if not is_descendant(pid, launcher.pid, processes):
            continue
        try:
            snapshot = native_process_snapshot(pid, token, binary)
            if snapshot is not None:
                observations.append(snapshot)
        except OSError as error:
            observations.append({'pid': pid, 'snapshot_error': repr(error)})
    return observations


def stop(actor):
    child, stdout, stderr, argv = actor
    before = child.poll()
    if before is None:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
    stdout.close()
    stderr.close()
    return {'argv': argv, 'launcher_pid': child.pid, 'exit_before_cleanup': before,
            'waited_exit': child.returncode, 'launcher_reaped': child.poll() is not None}


def capture(root, binary, host, modules, native_action='Reject'):
    with ExitStack() as resources:
        return _capture(root, binary, host, modules, native_action, resources)


def capture_profile(root, binary, host_port, native_action, profile):
    folder = root / profile
    folder.mkdir(mode=0o700)
    spool = folder / 'spool'
    spool.mkdir(mode=0o700)
    rules = folder / 'rules.conf'
    rules.write_text('\n'.join([
        'SecRuleEngine On', 'SecRequestBodyAccess On', 'SecRequestBodyLimit 4096',
        'SecRequestBodyNoFilesLimit 4096', 'SecRequestBodyLimitAction ' + native_action,
        'SecResponseBodyAccess On', 'SecResponseBodyMimeType text/plain',
        'SecResponseBodyLimit 4096', 'SecResponseBodyLimitAction ' + native_action,
        'SecRule REQUEST_URI "@contains p1-block" "id:9911201,phase:1,deny,status:451,log"',
        'SecRule REQUEST_BODY "@contains p2-marker" "id:9911202,phase:2,deny,status:418,log"',
        'SecRule REQUEST_URI "@contains p3-block" "id:9911203,phase:3,deny,status:422,log"',
        'SecRule RESPONSE_BODY "@contains stock-p4-marker" "id:9911204,phase:4,pass,log"',
        'SecRule REQUEST_URI "@contains p4-block" "id:9911205,phase:4,deny,status:429,log"', '']))
    rules.chmod(0o600)
    template = REPO / f'examples/lighttpd/stock/{profile}/msconnector-runtime.conf'
    runtime = folder / 'runtime.conf'
    runtime.write_text('\n'.join(
        f'rules_file={rules}' if line.startswith('rules_file=') else
        f'event_path={folder}/events.jsonl' if line.startswith('event_path=') else line
        for line in template.read_text().splitlines()) + '\n')
    runtime.chmod(0o600)
    port = free_port()
    env = dict(os.environ, MSCONNECTOR_LIGHTTPD_NATIVE_OBSERVER=str(folder / 'native.jsonl'),
               MSCONNECTOR_LIGHTTPD_HOST_OBSERVER=str(folder / 'host-eos.jsonl'),
               MSCONNECTOR_LIFECYCLE_RUN='i12-lighttpd-stock-20261015',
               MSCONNECTOR_LIFECYCLE_PROFILE='lighttpd-stock-sidecar',
               MSCONNECTOR_LIFECYCLE_CASE='supplement-' + profile)
    sidecar = launch(folder, 'sidecar', [binary, '--config', runtime, '--listen',
        f'127.0.0.1:{port}', '--upstream', f'127.0.0.1:{host_port}', '--timeout-ms', '1000',
        '--spool-directory', spool, '--spool-capacity-bytes', '65536',
        '--spool-free-reserve-bytes', '1048576'], env)
    result = {'profile': profile, 'template_sha256': sha(template), 'observations': [],
              'uid': os.geteuid(), 'native_limit_action': native_action,
              'full_lifecycle_qualified': False, 'oracle_evaluated': False}
    try:
        ready(port, sidecar[0])
        result['native_process_before'] = process_snapshot(sidecar[0], binary)
        before_backend = (root / BACKEND_LOG).read_text().splitlines() if (root / BACKEND_LOG).exists() else []

        def held_request(sidecar=sidecar, result=result, before_backend=before_backend):
            result['held_body_snapshot'] = process_snapshot(sidecar[0], binary)
            during = (root / BACKEND_LOG).read_text().splitlines() if (root / BACKEND_LOG).exists() else []
            result['backend_requests_before_replay_admission'] = len(during) - len(before_backend)

        result['held_replay_request'] = request(port, BODY_PATH, b'x' * 3000, hold=held_request)
        multipart = b'--i12\r\nContent-Disposition: form-data; name="one"\r\n\r\nhello\r\n--i12\r\nContent-Disposition: form-data; name="two"\r\n\r\nworld\r\n--i12--\r\n'
        result['multipart_request'] = request(port, BODY_PATH, multipart,
            content_type='multipart/form-data; boundary=i12')
        for name, path, body, reset in (
            ('allow', BODY_PATH, b'body', False), ('empty', EMPTY_PATH, b'', False),
            ('p1', '/p1-block', b'', False), ('p2', BODY_PATH, b'p2-marker', False),
            ('limit-reject', BODY_PATH, b'x' * 4097, False),
            ('p3', '/p3-block', b'', False), ('historical-rst-control', BODY_PATH, b'', True),
            ('p4-disruptive', '/p4-block', b'', False),
            ('response-native-limit', '/response-large', b'', False),
            ('response-mime-out', '/mime-out', b'', False),
            ('neighbor', EMPTY_PATH, b'neighbor', False)):
            before = (folder / EVENT_LOG).read_bytes() if (folder / EVENT_LOG).exists() else b''
            observation = {'case': name, **request(port, path, body, reset)}
            time.sleep(.08)
            after = (folder / EVENT_LOG).read_bytes() if (folder / EVENT_LOG).exists() else b''
            observation['physical_event_append_bytes'] = len(after) - len(before)
            result['observations'].append(observation)
        result['execution_status'] = 'observed'
    except (OSError, RuntimeError) as error:
        result['execution_status'] = 'blocked'
        result['error'] = str(error)
    finally:
        result['cleanup'] = stop(sidecar)
        result['spool_remaining_names'] = sorted(p.name for p in spool.iterdir())
        result['spool_mode'] = oct(stat.S_IMODE(spool.stat().st_mode))
        result['physical_files'] = {p.name: {'sha256': sha(p), 'size': p.stat().st_size,
            'mode': oct(stat.S_IMODE(p.stat().st_mode))} for p in folder.iterdir() if p.is_file()}
        write(folder / 'observations.json', result)
    return result


def _capture(root, binary, host, modules, native_action, resources):
    docroot = root / 'htdocs'
    docroot.mkdir(mode=0o700)
    (docroot / 'body.txt').write_text('stock-p4-marker')
    (docroot / 'empty.txt').write_bytes(b'')
    host_port = free_port()
    backend_lock = threading.Lock()

    class Backend(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            content = b'stock-p4-marker'
            if self.path == EMPTY_PATH:
                content = b''
            elif self.path == '/response-large':
                content = b'x' * 5000
            mime = 'application/octet-stream' if self.path == '/mime-out' else 'text/plain'
            with backend_lock, (root / BACKEND_LOG).open('a') as stream:
                stream.write(json.dumps({'method': self.command, 'path': self.path,
                    'monotonic_ns': time.monotonic_ns(), 'request_body_bytes': len(body),
                    'request_body_sha256': hashlib.sha256(body).hexdigest(),
                    'response_body_bytes': len(content), 'MIME': mime,
                    'request_content_type': self.headers.get('Content-Type')}) + '\n')
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *_args):
            # Raw protocol and native logs are retained separately; suppress
            # unrelated BaseHTTPRequestHandler console access logging.
            pass

    backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
    resources.callback(backend.server_close)
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
    backend_thread.start()
    resources.callback(backend_thread.join, timeout=5)
    resources.callback(backend.shutdown)
    config = root / 'lighttpd.conf'
    config.write_text('\n'.join([
        'server.compat-module-load = "disable"',
        'server.modules = ( "mod_accesslog", "mod_proxy" )',
        f'server.document-root = "{docroot}"', 'server.bind = "127.0.0.1"',
        f'server.port = {host_port}', f'server.errorlog = "{root}/host-error.log"',
        f'accesslog.filename = "{root}/host-access.log"',
        f'proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => {backend.server_port} ) ) )', '']))
    run(root, 'host-version', [host, '-v'])
    run(root, 'host-configtest', [host, '-tt', '-m', modules, '-f', config])
    actor = launch(root, 'host', [host, '-D', '-m', modules, '-f', config], dict(os.environ))
    resources.callback(stop, actor)
    rows = []
    try:
        ready(host_port, actor[0])
        for profile in PROFILES:
            rows.append(capture_profile(root, binary, host_port, native_action, profile))
    finally:
        cleanup = stop(actor)
        write(root / 'host-cleanup.json', cleanup)
        backend.shutdown()
        backend.server_close()
        backend_thread.join(timeout=5)
        write(root / 'backend-cleanup.json', {'thread_joined': not backend_thread.is_alive(),
                                            'server_closed': True})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--host', required=True, type=Path)
    parser.add_argument('--modules', required=True, type=Path)
    parser.add_argument('--native-limit-action', choices=('Reject', 'ProcessPartial'), default='Reject')
    args = parser.parse_args()
    os.umask(0o077)
    root = private_root(args.output)
    write(root / 'preflight.json', {'uid': os.geteuid(), 'gid': os.getegid(),
        'proc_status': Path('/proc/self/status').read_text(),
        'apparmor': Path('/proc/self/attr/current').read_text().strip(),
        'host': str(args.host), 'host_sha256': sha(args.host), 'runner_sha256': sha(__file__),
        'true_nonroot_executed': os.geteuid() != 0, 'full_lifecycle_qualified': False})
    try:
        binary = prepare(root)
        rows = capture(root, binary, args.host, args.modules, args.native_limit_action)
        write(root / 'summary.json', {'profiles': rows, 'full_lifecycle_qualified': False,
            'uncovered': ['true_nonroot' if os.geteuid() == 0 else None,
                          'spool-capacity-contention', 'free-reserve-exhaustion'],
            'historical_rst': 'fresh control only; original source binding required for reproduction'})
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        write(root / 'blocked.json', {'error': str(error), 'full_lifecycle_qualified': False})
        return 77
    return 77 if any(row['execution_status'] == 'blocked' for row in rows) else 0


if __name__ == '__main__':
    raise SystemExit(main())
