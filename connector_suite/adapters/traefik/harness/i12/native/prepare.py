"""Prepare source-only central capture inputs for a fresh isolated Traefik run.

The reviewed controller is supplied separately. This script never launches it.
Historical source snapshots supply build scaffolding, never runtime evidence.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat

ADMISSION_FILE = 'admission.json'
GO_VERSION = 'go1.27.2'
GO_SHA256 = '548d3c32f83fa81152f543eb1526be7884cfe0526eb5e9ce29d3eca14786e7e0'
GO_NAMESPACE_ROOT = '/mnt/artifacts/toolchains/' + GO_VERSION


def validate_private_toolchain(root):
    """Inventory a physical, regular tree without following symbolic links."""
    root = Path(root)
    if not root.is_absolute() or '..' in root.parts or root.resolve() != root:
        raise ValueError('physical absolute private toolchain source required')
    if any(path.is_symlink() for path in (root, *root.parents)) or not root.is_dir():
        raise ValueError('physical private toolchain directory required')
    inventory = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            inventory[str(path.relative_to(root))] = sha(path)
        elif not stat.S_ISDIR(mode):
            raise ValueError('private toolchain requires nonsymlink regular files/directories')
    version = root / 'VERSION'
    if 'VERSION' not in inventory or version.read_text().splitlines()[0:1] != [GO_VERSION]:
        raise ValueError('private toolchain VERSION must be go1.27.2')
    if inventory.get('bin/go') != GO_SHA256:
        raise ValueError('private toolchain bin/go SHA256 mismatch')
    if not (root / 'bin/go').stat().st_mode & 0o111:
        raise ValueError('private toolchain bin/go must be executable')
    return inventory


def stage_private_toolchain(root, artifacts, inventory):
    destination = artifacts / 'toolchains' / GO_VERSION
    if root == destination or root in destination.parents:
        raise ValueError('private toolchain destination must be outside source')
    shutil.copytree(root, destination, symlinks=True)
    copied = validate_private_toolchain(destination)
    if copied != inventory:
        raise ValueError('private toolchain changed during copy')
    return {'private_source_root': str(root), 'namespace_root': GO_NAMESPACE_ROOT,
            'version': GO_VERSION, 'go_sha256': GO_SHA256, 'files': copied,
            'system_toolchain_changed': False, 'GOTOOLCHAIN': 'local'}


def validate_physical_destination(path, storage):
    for item in (path, *path.parents, storage, *storage.parents):
        if item.is_symlink():
            raise ValueError('symlink output components are forbidden')
    if path.resolve() != path or storage.resolve() != storage:
        raise ValueError('physical output path required')
    if not storage.is_dir() or storage not in path.parents:
        raise ValueError('output outside configured external storage')
    validate_non_checkout_ancestors(path, storage)


def validate_non_checkout_ancestors(path, storage):
    for ancestor in (path, *path.parents):
        if ancestor.exists():
            metadata = ancestor.stat()
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
                raise ValueError('output ancestry must be private and task-owned')
        if ancestor == storage:
            break
        metadata = ancestor / '.git'
        if metadata.exists() or metadata.is_symlink():
            raise ValueError('Git checkout/metadata destination is forbidden')


def validate_output(path, *, fresh):
    """Reject unsafe destinations before copying, creating or chmodding anything.

    The configured storage root is a control-plane boundary, not a candidate
    checkout. Its own Git metadata is outside the disposable destination tree.
    """
    path = Path(path)
    configured = os.environ.get('CODEX_TEMP_ROOT')
    if not configured:
        raise ValueError('configured external storage root required')
    storage = Path(configured)
    if not path.is_absolute() or not storage.is_absolute() or '..' in path.parts:
        raise ValueError('absolute normalized external output required')
    validate_physical_destination(path, storage)
    if fresh and path.exists():
        raise ValueError('fresh output required')
    if not fresh and not path.is_dir():
        raise ValueError('existing physical output directory required')
    return path


def validate_prepared_root(root):
    root = validate_output(root, fresh=False)
    for name in ('source', 'fixtures', 'artifacts'):
        validate_output(root / name, fresh=False)
    return root


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('central driver template changed: ' + before[:80])
    return text.replace(before, after)


def seal(root):
    inventory = {'files': {}, 'symlinks': {}}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink prohibited: ' + str(path))
        if path.is_file():
            inventory['files'][str(path.relative_to(root))] = sha(path)
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
    for path in sorted(root.rglob('*'), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    root.chmod(0o555)
    return inventory


def refresh_capture_source(repo, source, registry, overlays):
    exporter_path = source_path('connectors/traefik/harness/i12') / 'source_export.py'
    exporter = load_source(exporter_path)
    snapshot = exporter.export(repo, source)
    central = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
        'i12_capture_apply', registry.root / 'capture_sources.py'))
    central.__spec__.loader.exec_module(central)
    adapter = load_source(source_path('connectors/traefik/harness/i12') / 'current_capture.py')
    receipt = adapter.apply(central, registry, 'traefik-native', source)
    for relative, before in receipt['actual_before_sha256'].items():
        after = receipt['exact_written_sha256'][relative]
        if before != after:
            overlays[relative] = {'before_sha256': before, 'instrumented_sha256': after,
                                 'scope': 'central traefik-native observation with exact current-product adapter'}
    return {name: entry['sha256'] for name, entry in snapshot['files'].items()}


def stage_fixtures(fixtures, profile, registry):
    fixtures.mkdir()
    for relative, entry in profile['capture_files'].items():
        if relative.startswith('drivers/'):
            path = fixtures / Path(relative).name
            path.write_bytes(registry.content(entry['sha256']))
            if path.suffix == '.sh':
                path.chmod(0o700)
    for name in ('client.py', 'backend.py'):
        shutil.copyfile(Path(__file__).parent / name, fixtures / name)


def prepare(repo, historical, output, private_toolchain):
    # Reject the destination before traversing any caller-supplied input tree.
    # Both inputs are fully validated before the first directory is created.
    output = validate_output(output, fresh=True)
    toolchain_inventory = validate_private_toolchain(private_toolchain)
    output.mkdir(parents=True, mode=0o700)
    source, fixtures = output / 'source', output / 'fixtures'
    capture_root = repo / 'ci/runtime/lifecycle/i12'
    module = load_source(capture_root / 'capture_sources.py')
    registry = module.Registry(capture_root, repo)
    profile = registry.manifest['profiles']['traefik-native']
    overlays = {}
    bindings = refresh_capture_source(repo, source, registry, overlays)
    revision = json.loads((source / '.i12-source-export-manifest.json').read_text())['source_revision']
    stage_fixtures(fixtures, profile, registry)
    driver = (fixtures / 'driver.py').read_text()
    driver = replace_once(driver, "RUN = 'tf-i12-eos-20261014'", "RUN = 'tf-i12-native-20261015'")
    driver = replace_once(driver, "'delivery_base': '02754040bced960cfc1857416cd7101bb3116ef4'", "'delivery_base': " + repr(revision))
    driver = replace_once(driver, "'product_base': 'a9d48bb58aa948aea7d79e20cdf09d3f239b7808'", "'product_base': " + repr(revision))
    start = driver.index('    product = json.loads(')
    end = driver.index("    write('build-manifest.json'", start)
    driver = driver[:start] + "    write('current-product-binding.json', json.loads((FIXTURES / 'current-product-binding.json').read_text()))\n" + driver[end:]
    driver = replace_once(driver, "    os.environ.update(env)", "    os.environ.update(env)")
    marker = "    (TASK / 'rules.conf').write_text('\\n'.join(rules) + '\\n')"
    additions = '''    rules.extend([
        'SecRule REQUEST_URI "@streq /i12-eos-p1-deny" "id:1999201,phase:1,deny,status:403,log"',
        'SecRule REQUEST_BODY "@contains i12-p2-deny" "id:1999202,phase:2,deny,status:403,log"',
        'SecRule RESPONSE_HEADERS:X-I12-P3 "@streq deny" "id:1999203,phase:3,deny,status:403,log"',
        'SecRule RESPONSE_BODY "@contains p4-safe-late" "id:1999204,phase:4,deny,status:403,log"',
        'SecRule RESPONSE_BODY "@contains i12-response-marker" "id:1999205,phase:4,pass,log,msg:\\'i12-mime-body-proof\\'"'])
'''
    driver = replace_once(driver, marker, additions + marker)
    old = "        for label, nonce in (('target', TARGET), ('neighbor', NEIGHBOR)):\n            transaction_id = 'tf-' + nonce\n            execute(f'client-{label}', ['/usr/local/bin/python3', '-P', FIXTURES / 'client.py', str(host_port),\n                                      nonce, transaction_id, label], env)\n            time.sleep(0.15)\n            snapshot(f'after-{label}', processes)"
    new = "        for label, expected in (('allow-chunks',200),('p1-deny',403),('p2-deny',403),('p3-deny',403),('p4-safe-late',200),('mime-out',200),('neighbor',200)):\n            execute(f'client-{label}', ['/usr/local/bin/python3', '-P', FIXTURES / 'client.py', str(host_port), label, str(expected)], env)\n            time.sleep(0.15)\n            snapshot(f'after-{label}', processes)"
    driver = replace_once(driver, old, new)
    driver = driver.replace("'selected_case_count': 1", "'selected_case_count': 6")
    (fixtures / 'driver.py').write_text(driver)
    save(fixtures / 'current-product-binding.json', {'checkout': str(repo), 'checkout_base': json.loads((source / '.i12-source-export-manifest.json').read_text())['source_revision'],
         'product_inputs': bindings, 'capture_overlays': overlays, 'central_manifest_sha256': sha(capture_root / 'manifest.json'),
         'historical_host_artifact_inputs': str(historical / 'sealed-common-inputs/artifacts/traefik'), 'runtime_replay': False})
    shutil.copytree(historical / 'sealed-common-inputs/artifacts/traefik', output / 'artifacts/traefik')
    toolchain_binding = stage_private_toolchain(private_toolchain, output / 'artifacts', toolchain_inventory)
    save(fixtures / 'toolchain-input-binding.json', toolchain_binding)
    ledgers = {}
    for name in ('source', 'fixtures', 'artifacts'):
        ledger = output / (name + '-ledger.json')
        save(ledger, seal(output / name))
        ledger.chmod(0o444)
        ledgers[name] = ledger
    admission = {'mode': 'nonroot', 'timeout_seconds': 1000, 'setup_timeout_seconds': 120,
                 'resource_limits': {'memory_bytes': 3221225472, 'processes': 384, 'output_bytes': 2147483648},
                 'argv': ['/usr/local/bin/python3', '-P', '/mnt/fixtures/driver.py'],
                 'bindings': [{'source': str(output / name), 'target': target, 'ledger': str(ledgers[name]),
                               'ledger_sha256': sha(ledgers[name])} for name, target in
                              [('source', '/mnt/src'), ('fixtures', '/mnt/fixtures'), ('artifacts', '/mnt/artifacts')]],
                 'environment': {'CONNECTOR_ROOT': '/mnt/src'}}
    save(output / ADMISSION_FILE, admission)
    (output / ADMISSION_FILE).chmod(0o444)
    print(json.dumps({'prepared': str(output), 'admission_sha256': sha(output / ADMISSION_FILE), 'runtime_qualified': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--historical', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-toolchain', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.repo.resolve(), args.historical.resolve(), args.output, args.private_toolchain)
