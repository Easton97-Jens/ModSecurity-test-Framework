"""Regenerate sealed current Traefik observations from a reviewed byte recipe.

No host is launched. Historical content identities are never changed. Changed
repository objects are recovered from exact reviewed Git blobs into inert JSON.
Current product outputs require both pinned inputs and independent output pins.
"""
import argparse
import copy
import difflib
import json
from pathlib import Path
import re
import subprocess

from modsecurity_test_framework.connector_context import (
    connector_root, load_source, source_path, test_root,
)

HERE = Path(__file__).resolve().parent


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def historical_anchor_model(name, before, after):
    """Port historical anchors, never copy these model bytes into product.

    The runtime member moved into completion. Native commit accounting gained
    an error variable and an acknowledging callback. Only matching models change;
    the strict two-line anchor algorithm still preserves the actual source.
    """
    if name == 'common/runtime/msconnector_runtime.c':
        before = before.replace(b'->response_companion_handed_off',
                                b'->completion.response_companion_handed_off')
        after = after.replace(b'->response_companion_handed_off',
                              b'->completion.response_companion_handed_off')
    if name == 'connectors/traefik/native_middleware/middleware.go':
        before = before.replace(b'\tcount, writeErr := writer.target.Write(chunk)\n',
            b'\tcount, writeErr := writer.target.Write(chunk)\n\tvar commitErr error\n')
        after = after.replace(
            b'\tif count > 0 {\n\t\twriter.state.markResponseCommit(writer.requestContext(), 0, true, true)',
            b'\tvar commitErr error\n\tif count > 0 {\n\t\twriter.state.markResponseCommit(writer.requestContext(), 0, true, true)')
        before = before.replace(
            b'writer.state.markResponseCommit(writer.requestContext(), status, true, false)',
            b'writer.markResponseCommit(status, true, false)')
        after = after.replace(
            b'writer.state.markResponseCommit(writer.requestContext(), status, true, false)',
            b'writer.markResponseCommit(status, true, false)')
    return before, after


def git_blob(row):
    repository = connector_root() if row['repository'] == 'parent' else test_root()
    return subprocess.check_output(['rtk', 'bypass', 'git', '-C', str(repository),
        'show', row['revision'] + ':' + row['path']])


def generate():
    central = load_source(source_path('ci/runtime/lifecycle/i12/capture_sources.py'))
    adapter = load_source(HERE / 'current_capture.py')
    recipe = json.loads((HERE / 'capture_recipe.json').read_text())
    registry = central.Registry(source_path('ci/runtime/lifecycle/i12'), connector_root())
    manifest = copy.deepcopy(registry.manifest)
    generated = {}

    def add_file(path, data):
        generated[path] = data

    for row in recipe['historical_objects']:
        identity = row['identity']
        data = git_blob(row)
        if central.digest(data) != identity:
            raise ValueError('Reviewed historical Git blob differs: ' + row['logical_path'])
        filename = 'objects/text/' + identity + '-historical.lines.json'
        add_file(registry.root / filename, encoded(data.decode().splitlines(keepends=True)))
        item = {'kind': 'text_lines', 'file': filename,
                'historical_git': {key: row[key] for key in ('repository', 'revision', 'path')}}
        manifest['objects'][identity] = item
        registry.cache[identity] = data
    # Keep strict global validation; unrelated historical variants retain bytes.
    registry.verify()

    for name, expected in recipe['current_inputs'].items():
        data = central.plain(source_path(name))
        if central.digest(data) != expected:
            raise ValueError('Reviewed current input differs: ' + name)

    preservation = {}
    for profile_name, historical in recipe['historical_targets'].items():
        profile = manifest['profiles'][profile_name]
        targets = {}
        for name, entry in historical.items():
            if name not in recipe['current_inputs']:
                targets[name] = entry
                continue
            current = central.plain(source_path(name))
            input_hash = central.digest(current)
            manifest['objects'][input_hash] = {'kind': 'repository', 'path': name}
            framework_owned = source_path(name).is_relative_to(test_root())
            if framework_owned:
                # The migrated helper is not in a committed Parent export.
                # Retain current ABI/admission/finalize code byte for byte.
                output = current
            elif entry['before_sha256'] == entry['sha256']:
                output = current
            else:
                before, after = historical_anchor_model(name,
                    registry.content(entry['before_sha256']), registry.content(entry['sha256']))
                output, _ = adapter.observation_delta(central, before, after, current)
            if central.digest(output) != recipe['expected_outputs'][profile_name][name]:
                raise ValueError('Independent reviewed output differs: ' + name)
            targets[name] = store_output(central, manifest, generated, registry.root,
                                        name, current, output, framework_owned)
            preservation[profile_name + ':' + name] = preserved_spans(central, current, output)
        if profile_name == 'traefik-forwardauth':
            name = adapter.PROVENANCE
            current = central.plain(source_path(name))
            output, _ = adapter.provenance_observation(central, current)
            if central.digest(output) != recipe['expected_outputs'][profile_name][name]:
                raise ValueError('Independent reviewed provenance output differs')
            manifest['objects'][central.digest(current)] = {'kind': 'repository', 'path': name}
            targets[name] = store_output(central, manifest, generated, registry.root,
                                        name, current, output, False)
            preservation[profile_name + ':' + name] = preserved_spans(central, current, output)
        profile['source_targets'] = targets
        profile['required_source_identity_format'] = 'i12-disposable-source-copy-v2'
        profile['current_capture_recipe_sha256'] = central.digest((HERE / 'capture_recipe.json').read_bytes())
    add_file(registry.root / 'manifest.json', encoded(manifest))
    contract = {'schema_version': 1,
        'profile_hashes': {name: central.digest(adapter.canonical(manifest['profiles'][name]))
                          for name in recipe['historical_targets']},
        'central_hash': central.digest(central.plain(registry.root / 'capture_sources.py')),
        'current': recipe['current_inputs'], 'outputs': recipe['expected_outputs'],
        'preserved_spans': preservation}
    contract_bytes = encoded(contract)
    add_file(HERE / 'capture_contract.json', contract_bytes)
    adapter_bytes = (HERE / 'current_capture.py').read_text()
    adapter_bytes, count = re.subn(r"CONTRACT_HASH = '[a-f0-9]{64}'",
        "CONTRACT_HASH = '" + central.digest(contract_bytes) + "'", adapter_bytes)
    if count != 1:
        raise ValueError('Single adapter seal declaration required')
    add_file(HERE / 'current_capture.py', adapter_bytes.encode())
    return generated


def preserved_spans(central, current, output):
    """Bind each untouched byte span, including changed-product security code."""
    before, after = current.splitlines(keepends=True), output.splitlines(keepends=True)
    spans = []
    for block in difflib.SequenceMatcher(None, before, after, autojunk=False).get_matching_blocks():
        if block.size:
            data = b''.join(before[block.a:block.a + block.size])
            spans.append({'input_start': sum(map(len, before[:block.a])),
                          'output_start': sum(map(len, after[:block.b])),
                          'size': len(data), 'sha256': central.digest(data)})
    return spans


def store_output(central, manifest, generated, root, name, current, output, framework_owned):
    identity = central.digest(output)
    input_hash = central.digest(current)
    entry = {'before_sha256': None if framework_owned else input_hash,
             'sha256': identity, 'mode': 420}
    if framework_owned:
        entry['framework_input_sha256'] = input_hash
    if output != current:
        patch = ''.join(difflib.unified_diff(current.decode().splitlines(True),
            output.decode().splitlines(True), fromfile='a/payload', tofile='b/payload', n=3)).encode()
        if central.exact_patch(current, patch) != output:
            raise ValueError('Generated current delta differs')
        patch_hash = central.digest(patch)
        filename = 'objects/deltas/' + patch_hash + '-' + Path(name).name + '.patch.lines.json'
        generated[root / filename] = encoded(patch.decode().splitlines(keepends=True))
        manifest['objects'][identity] = {'kind': 'delta', 'base': input_hash,
                                        'patch': filename, 'patch_kind': 'text_lines',
                                        'patch_sha256': patch_hash}
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate()
    changed = [str(path) for path, data in generated.items()
               if not path.exists() or path.read_bytes() != data]
    if args.check:
        if changed:
            parser.exit(1, 'Generated capture differs: ' + ', '.join(changed) + '\n')
    else:
        for path, data in generated.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(json.dumps({'generated_files': len(generated), 'changed_files': len(changed),
                      'source_copy_only': True, 'runtime_qualified': False}))


if __name__ == '__main__':
    main()
