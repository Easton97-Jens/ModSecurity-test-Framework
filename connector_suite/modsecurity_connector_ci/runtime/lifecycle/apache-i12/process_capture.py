"""Physical same-process snapshots shared by the Apache-only host launchers."""
import hashlib
import json
import os
from pathlib import Path
import time


def capture_process(pid, expected_starttime=None):
    proc = Path('/proc') / str(pid)
    starttime = proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
    if expected_starttime is not None and str(starttime) != str(expected_starttime):
        raise RuntimeError('Native child PID starttime differs from the supervisor lease')
    stamp = time.monotonic_ns()
    destination = Path('/task/native-process')
    destination.mkdir(mode=0o700, exist_ok=True)
    texts = {kind: proc.joinpath(kind).read_text() for kind in ('maps', 'status')}
    fds = {entry.name: os.readlink(entry) for entry in proc.joinpath('fd').iterdir()}
    for kind, text in texts.items():
        destination.joinpath(f'{stamp}.{kind}').write_text(text)
    destination.joinpath(f'{stamp}.fds.json').write_text(json.dumps(fds, indent=2) + '\n')
    return {'monotonic_ns': stamp, 'native_child_pid': pid, 'starttime': starttime,
            'fd_count': len(fds), 'files_label': str(stamp),
            **{f'{kind}_sha256': hashlib.sha256(text.encode()).hexdigest()
               for kind, text in texts.items()}}
