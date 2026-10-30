"""Export committed Parent regular files, with complete pre-capture identity."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess

MARKER = '.i12-disposable-source-copy.json'
SNAPSHOT = '.i12-source-export-manifest.json'


def git(repository, *arguments, data=None):
    return subprocess.run(['rtk', 'proxy', 'git', '-C', str(repository), *arguments],
                          input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True).stdout


def bounded_path(name):
    path = Path(name)
    if (not name or path.is_absolute() or '\\' in name or
            any(part in ('', '.', '..', '.git') for part in name.split('/'))):
        raise ValueError('invalid committed source path')
    return path


def entries(repository, revision):
    files, gitlinks = [], {}
    for row in git(repository, 'ls-tree', '-rz', revision).split(b'\0'):
        if not row:
            continue
        metadata, raw_name = row.split(b'\t', 1)
        mode, kind, identity = metadata.decode('ascii').split(' ')
        name = raw_name.decode('utf-8')
        bounded_path(name)
        if mode == '160000' and kind == 'commit':
            gitlinks[name] = identity
        elif mode in ('100644', '100755') and kind == 'blob':
            files.append((name, 493 if mode == '100755' else 420, identity))
        else:
            raise ValueError('committed symlink or unsupported Git object: ' + name)
    if not files:
        raise ValueError('empty Parent source inventory')
    return files, gitlinks


def validate_private_ancestor(ancestor, storage):
    if ancestor.is_symlink():
        raise ValueError('symlink source destination forbidden')
    if ancestor.exists():
        info = ancestor.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('source destination must be private and task-owned')
    if ancestor != storage and ((ancestor / '.git').exists() or (ancestor / '.git').is_symlink()):
        raise ValueError('Git source destination forbidden')


def validate_destination(destination):
    configured = os.environ.get('CODEX_TEMP_ROOT')
    if not configured:
        raise ValueError('configured external storage root required')
    storage = Path(configured)
    if (not destination.is_absolute() or not storage.is_absolute() or
            destination.resolve() != destination or storage.resolve() != storage or
            not storage.is_dir() or storage not in destination.parents):
        raise ValueError('physical external source destination required')
    for ancestor in (destination, *destination.parents):
        validate_private_ancestor(ancestor, storage)
        if ancestor == storage:
            break


def export(repository, destination):
    """Caller must first validate its private external destination boundary.

    Working-tree modifications and untracked producers are intentionally absent.
    Their fixture/instrumentation bindings must be recorded separately.
    """
    repository, destination = Path(repository), Path(destination)
    validate_destination(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('fresh source export required')
    revision = git(repository, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    tree = git(repository, 'rev-parse', '--verify', revision + '^{tree}').decode().strip()
    files, gitlinks = entries(repository, revision)
    requests = ''.join(identity + '\n' for _, _, identity in files).encode('ascii')
    objects = io.BytesIO(git(repository, 'cat-file', '--batch', data=requests))
    destination.mkdir(mode=0o700)
    inventory = {}
    for name, mode, identity in files:
        header = objects.readline().decode('ascii').strip().split(' ')
        if len(header) != 3 or header[:2] != [identity, 'blob']:
            raise ValueError('Git source object response differs')
        size = int(header[2])
        data = objects.read(size)
        if len(data) != size or objects.read(1) != b'\n':
            raise ValueError('incomplete Git source object')
        blob = b'blob ' + str(size).encode('ascii') + b'\0' + data
        if hashlib.sha1(blob, usedforsecurity=False).hexdigest() != identity:
            raise ValueError('Git source object identity differs')
        path = destination / bounded_path(name)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open('xb') as output:
            output.write(data)
        path.chmod(mode)
        inventory[name] = {'mode': mode, 'sha256': hashlib.sha256(data).hexdigest()}
    if objects.read():
        raise ValueError('unexpected Git source response bytes')
    snapshot = {'format': 'i12-source-export-manifest-v1', 'source_revision': revision,
                'git_tree': tree, 'files': inventory, 'gitlinks': gitlinks}
    data = (json.dumps(snapshot, indent=2, sort_keys=True) + '\n').encode()
    (destination / SNAPSHOT).write_bytes(data)
    marker = {'format': 'i12-disposable-source-copy-v2', 'path': str(destination),
              'disposable': True, 'source_revision': revision, 'snapshot_manifest': SNAPSHOT,
              'snapshot_manifest_sha256': hashlib.sha256(data).hexdigest()}
    (destination / MARKER).write_text(json.dumps(marker, indent=2) + '\n')
    return snapshot
