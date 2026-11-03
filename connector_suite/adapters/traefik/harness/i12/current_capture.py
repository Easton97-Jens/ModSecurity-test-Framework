"""Apply sealed Traefik observation deltas to an exact current v2 export.

Central variants and fixtures remain the authority for observation bytes. This
adapter preserves current product code instead of treating an accepted current
input hash as permission to overwrite it with a historical product snapshot.
All changes are planned and hash checked before writing the disposable copy.
"""
import difflib
import hashlib
import json
from pathlib import Path
from modsecurity_test_framework.connector_context import framework_revision, source_path

CONTRACT_HASH = 'a8165b97ae9f52338538109c7bdf2cbfb1c88fddaab115f1366227c9727b313b'

RUNTIME = 'common/runtime/msconnector_runtime.c'
AUTHORIZATION = 'common/runtime/http_authorization_service.c'
OBSERVER = 'connectors/traefik/response_observer/observer.go'
PROVENANCE = 'connectors/traefik/response_observer/provenance.go'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sealed_contract():
    data = Path(__file__).with_name('capture_contract.json').read_bytes()
    if digest(data) != CONTRACT_HASH:
        raise ValueError('Sealed current capture contract differs')
    return json.loads(data)


CONTRACT = sealed_contract()
PROFILE_HASHES = CONTRACT['profile_hashes']
CENTRAL_HASH = CONTRACT['central_hash']
CURRENT = CONTRACT['current']
OUTPUTS = CONTRACT['outputs']
# Compatibility name for the forwardAuth product observation outputs.
REBASED = {name: value for name, value in OUTPUTS['traefik-forwardauth'].items()
           if not name.startswith('ci/')}


def observation_delta(central, historical, observed, current):
    """Move only sealed edits through unchanged historical/current line spans.

    Every edit needs two unchanged adjacent anchor lines on each available
    side. No fuzzy patching, matching by text occurrence, or product deletion is
    permitted. The resulting unified delta is then applied by central's exact
    patch parser and independently checked against a pinned output digest.
    """
    before = historical.decode().splitlines(keepends=True)
    after = observed.decode().splitlines(keepends=True)
    source = current.decode().splitlines(keepends=True)
    blocks = difflib.SequenceMatcher(None, before, source, autojunk=False).get_matching_blocks()
    edits = []
    for operation, start, end, new_start, new_end in difflib.SequenceMatcher(
            None, before, after, autojunk=False).get_opcodes():
        if operation == 'equal':
            continue
        left, right = max(0, start - 2), min(len(before), end + 2)
        candidates = [(block.b + start - block.a, block.b + end - block.a)
                      for block in blocks if block.a <= left and right <= block.a + block.size]
        if len(candidates) != 1:
            raise ValueError('Observation edit overlaps changed current product code')
        actual_start, actual_end = candidates[0]
        edits.append((actual_start, actual_end, after[new_start:new_end]))
    result = list(source)
    for start, end, replacement in reversed(edits):
        result[start:end] = replacement
    patch = ''.join(difflib.unified_diff(source, result, fromfile='a/payload',
                                         tofile='b/payload', n=3)).encode()
    return central.exact_patch(current, patch), patch


def provenance_observation(central, current):
    text = current.decode()
    substitutions = (
        ('openSession(w.request.Context(), w.parent.config, handle)',
         'openSession(i12ObservedContext(w.request), w.parent.config, handle)'),
        ('openSession(ctx, w.parent.config, string(reply[2:]))',
         'openSession(context.WithValue(ctx, i12ObserverContextKey{}, i12RequestProbeID(w.request)), w.parent.config, string(reply[2:]))'),
    )
    for before, after in substitutions:
        if text.count(before) != 1:
            raise ValueError('Current provenance observation boundary differs')
        text = text.replace(before, after, 1)
    patch = ''.join(difflib.unified_diff(current.decode().splitlines(keepends=True),
        text.splitlines(keepends=True), fromfile='a/payload', tofile='b/payload', n=3)).encode()
    return central.exact_patch(current, patch), patch


def validate_capture(central, registry, profile_name, target):
    sealed_contract()
    expected_profile = PROFILE_HASHES.get(profile_name)
    if expected_profile is None:
        raise ValueError('Only sealed Traefik variants are supported')
    profile = registry.manifest['profiles'][profile_name]
    if digest(canonical(profile)) != expected_profile:
        raise ValueError('Sealed Traefik profile differs')
    if digest(central.plain(registry.root / 'capture_sources.py')) != CENTRAL_HASH:
        raise ValueError('Central capture implementation differs')
    identity = central.disposable(target, registry.manifest['delivery_product_baseline'],
        Path(registry.manifest['authorized_storage_root']))
    if identity['source_identity_format'] != 'i12-disposable-source-copy-v2':
        raise ValueError('Current Traefik capture requires a complete v2 export')
    if (target / central.RECEIPT).exists():
        raise ValueError('Source application receipt already exists')
    registry.verify()
    return identity, profile, expected_profile


def source_write(central, registry, profile_name, target, name, entry):
    path = target / central.relative(name)
    original = central.plain(path) if path.exists() else None
    actual = digest(original) if original is not None else None
    expected = entry['before_sha256']
    if actual != expected:
        raise ValueError('Exact current source-copy base differs: ' + name)
    output, delta = registry.content(entry['sha256']), None
    strategy = 'central-declared-output'
    if 'framework_input_sha256' in entry:
        bound = central.plain(source_path(name, root=registry.repository))
        if digest(bound) != entry['framework_input_sha256'] or output != bound:
            raise ValueError('Current Framework helper differs: ' + name)
        strategy = 'current-framework-source-bound'
    elif name in CURRENT:
        if original == output:
            strategy = 'current-product-preserved'
        else:
            delta = ''.join(difflib.unified_diff(original.decode().splitlines(keepends=True),
                output.decode().splitlines(keepends=True), fromfile='a/payload',
                tofile='b/payload', n=3)).encode()
            if central.exact_patch(original, delta) != output:
                raise ValueError('Current observation delta differs')
            strategy = 'sealed-observation-rebased-on-current-product'
    if name in CURRENT and digest(output) != OUTPUTS[profile_name].get(name):
        raise ValueError('Pinned current observation output differs: ' + name)
    transformation = {'strategy': strategy, 'input_sha256': actual, 'output_sha256': digest(output),
        'central_output_sha256': entry['sha256'],
        'central_object': registry.manifest['objects'][entry['sha256']],
        'applied_delta_sha256': digest(delta) if delta is not None else None}
    return (path, output, entry.get('mode', 420)), actual, transformation


def validate_writes(target, writes):
    for path, _, mode in writes:
        if not path.is_relative_to(target) or mode not in (420, 493):
            raise ValueError('Invalid current source-copy write')
        for parent in path.parents:
            if parent == target:
                break
            if parent.exists() and not parent.is_dir():
                raise ValueError('Current source-copy parent is not a directory')


def apply(central, registry, profile_name, target):
    """Validate the complete export and registry, then apply one exact variant."""
    target = Path(target)
    identity, profile, expected_profile = validate_capture(central, registry, profile_name, target)
    writes, inputs, transformations = [], {}, {}
    for name, entry in profile['source_targets'].items():
        write, inputs[name], transformations[name] = source_write(central, registry, profile_name, target, name, entry)
        writes.append(write)
    fixture_root = target / '.i12-capture' / profile_name
    if fixture_root.exists():
        raise ValueError('Capture destination already exists')
    for name, entry in profile['capture_files'].items():
        writes.append((fixture_root / central.relative(name), registry.content(entry['sha256']),
                       entry.get('mode', 420)))
    validate_writes(target, writes)
    receipt = {**identity, 'profile': profile_name, 'source_copy': str(target),
        'delivery_product_baseline': registry.manifest['delivery_product_baseline'],
        'capture_manifest_sha256': digest(central.plain(registry.root / 'manifest.json')),
        'central_implementation_sha256': CENTRAL_HASH, 'profile_sha256': expected_profile,
        'capture_contract_sha256': CONTRACT_HASH, 'framework_revision': framework_revision(),
        'framework_source_sha256': {name: entry['framework_input_sha256']
            for name, entry in profile['source_targets'].items() if 'framework_input_sha256' in entry},
        'adapter_sha256': digest(Path(__file__).read_bytes()), 'actual_before_sha256': inputs,
        'exact_written_sha256': {str(path.relative_to(target)): digest(data) for path, data, _ in writes},
        'transformations': transformations, 'source_copy_only': True, 'runtime_qualified': False}
    for path, data, mode in writes:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    with (target / central.RECEIPT).open('x', encoding='utf-8') as output:
        output.write(json.dumps(receipt, indent=2) + '\n')
    return receipt
