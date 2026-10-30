"""Fixed private parser child with physical wait status and file identities."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time


ENGINE = Path('/task/build/service/traefik-forwardauth')
SOURCE = Path('/mnt/src')


def file_identity(path):
    try:
        value = path.lstat()
    except OSError as error:
        return {'path': str(path), 'lstat_success': False, 'errno': error.errno,
                'monotonic_ns': time.monotonic_ns()}
    result = {'path': str(path), 'lstat_success': True, 'errno': None,
              'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid,
              'gid': value.st_gid, 'mode': stat.S_IMODE(value.st_mode),
              'regular_file': stat.S_ISREG(value.st_mode),
              'monotonic_ns': time.monotonic_ns()}
    if result['regular_file']:
        result['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def decode_wait(status):
    return {'raw_wait_status': status,
            'exit_code': os.WEXITSTATUS(status) if os.WIFEXITED(status) else None,
            'signal': os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0,
            'core_dumped': os.WCOREDUMP(status) if os.WIFSIGNALED(status) else False}


def wait_child(pid, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result, status = os.waitpid(pid, os.WNOHANG)
        if result == pid:
            return status, False
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    return status, True


def execute_child(engine_fd, argv, read_fd, write_fd, stdout_fd, stderr_fd):
    """Enter the pinned parser image and retain an exec failure before exit."""
    try:
        os.close(read_fd)
        os.chdir(SOURCE)
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        child = {'stage': 'child_pre_exec', 'pid': os.getpid(), 'ppid': os.getppid(),
                 'uid': os.geteuid(), 'gid': os.getegid(), 'cwd': os.getcwd(),
                 'monotonic_ns': time.monotonic_ns()}
        child_receipt = json.dumps(child) + '\n'
        os.write(write_fd, child_receipt.encode())
        os.execve(engine_fd, argv, os.environ.copy())
    except (OSError, ValueError, TypeError) as error:
        value = {'stage': 'exec_error', 'errno': getattr(error, 'errno', None),
                 'type': type(error).__name__, 'monotonic_ns': time.monotonic_ns()}
        error_receipt = json.dumps(value) + '\n'
        os.write(write_fd, error_receipt.encode())
        os._exit(127)


def execute(root,literal_minimal=False):
    if (os.geteuid(), os.getegid()) != (65534, 65534):
        raise RuntimeError('admitted nonroot parser identity required')
    if root.parent != Path('/task/cases') or not re.fullmatch(r'ac-[0-9a-f]{20}(?:-strict-admission)?', root.name):
        raise ValueError('fixed original case directory required')
    if root.resolve(strict=True) != root or os.execve not in os.supports_fd:
        raise RuntimeError('exact path and fd exec required')
    case = json.loads((root / 'case.json').read_text())
    if case['probe_id'] != root.name:
        raise ValueError('case identity mismatch')
    config = root / ('runtime/effective-config/unsupported-minimal.conf' if literal_minimal else 'runtime/effective-config/traefik-forwardauth.conf')
    label = 'literal-minimal-check-config' if literal_minimal else 'check-config'
    lines = config.read_text().splitlines()
    rules_values = [line.split('=', 1)[1] for line in lines if line.startswith('rules_file=')]
    if len(rules_values) != 1:
        raise ValueError('single effective rules_file required')
    rules = Path(rules_values[0])
    if rules not in (root / 'rules.conf', root / 'missing-rules.conf'):
        raise ValueError('fixed private rules path required')
    before = {'configuration': file_identity(config), 'rules': file_identity(rules)}
    engine_fd = os.open(ENGINE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    image = os.fstat(engine_fd)
    if not stat.S_ISREG(image.st_mode) or image.st_uid != os.geteuid() or image.st_mode & 0o022 or os.pread(engine_fd, 4, 0) != b'\x7fELF':
        os.close(engine_fd)
        raise RuntimeError('owned regular ELF parser image required')
    with os.fdopen(os.dup(engine_fd), 'rb') as stream:
        image_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    argv = [str(ENGINE), '--check-config', '--config', str(config)]
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    started = time.monotonic_ns()
    parent_pid = os.getpid()
    stdout_fd = os.open(root / (label + '.stdout'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stderr_fd = os.open(root / (label + '.stderr'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    pid = os.fork()
    if pid == 0:
        execute_child(engine_fd, argv, read_fd, write_fd, stdout_fd, stderr_fd)
    os.close(write_fd)
    os.close(stdout_fd)
    os.close(stderr_fd)
    os.close(engine_fd)
    status, timed_out = wait_child(pid)
    completed = time.monotonic_ns()
    child_rows = os.read(read_fd, 16384).decode().splitlines()
    os.close(read_fd)
    result = {'schema': 'traefik-auth-parser-process-v1', 'run_id': 'traefik-acceptance-20261015',
              'original_id': case['id'], 'probe': case['probe_id'], 'pid': pid,
              'parent_pid': parent_pid,
              'argv': argv, 'cwd': str(SOURCE), 'uid': os.geteuid(), 'gid': os.getegid(),
              'started_ns': started, 'completed_ns': completed, 'timed_out': timed_out,
              **decode_wait(status), 'child_receipts': [json.loads(line) for line in child_rows],
              'executable': {'path': str(ENGINE), 'sha256': image_sha, 'device': image.st_dev,
                             'inode': image.st_ino, 'uid': image.st_uid, 'exec_method': 'execve_exact_open_fd'},
              'files_before': before,
              'files_after': {'configuration': file_identity(config), 'rules': file_identity(rules)},
              'stdout_sha256': hashlib.sha256((root / (label + '.stdout')).read_bytes()).hexdigest(),
              'stderr_sha256': hashlib.sha256((root / (label + '.stderr')).read_bytes()).hexdigest(),
              'first_cause': None, 'independent_diagnostic_binding_required': True,
              'exit_status_normalized': False,
              'cleanup': {'waited_child_pid': pid, 'child_reaped': True,
                          'engine_fd_closed': True, 'receipt_pipe_closed': True,
                          'stdout_stderr_parent_fds_closed': True},
              'qualification': None}
    (root / (label + '.command.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--literal-minimal', action='store_true')
    args = parser.parse_args()
    measured = execute(args.case_root,args.literal_minimal)
    print(json.dumps({'parser_pid': measured['pid'], 'exit_code': measured['exit_code'],
                      'signal': measured['signal'], 'qualification': None}))
