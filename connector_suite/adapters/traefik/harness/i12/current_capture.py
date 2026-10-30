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


PROFILE_HASHES = {
    'traefik-native': 'a40b3dbe85f04a89970f689c26497d178bb1df3d6f24dfa56e0f1f6abb250683',
    'traefik-forwardauth': '27ecb4b122a9d873800177c2704a18c56293da6e2029af6854578cc4b793a9f2',
}
CENTRAL_HASH = '198c16b71cdd029d8f46ad5c48f7ab37d7d326be0529190b47ac73a98a7237bd'
RUNTIME = 'common/runtime/msconnector_runtime.c'
AUTHORIZATION = 'common/runtime/http_authorization_service.c'
OBSERVER = 'connectors/traefik/response_observer/observer.go'
PROVENANCE = 'connectors/traefik/response_observer/provenance.go'
CURRENT = {
    RUNTIME: '2224eb66d963b9ee4413175fdd89f5719ae214e0bd1efdb1e39d1eaf93f04451',
    AUTHORIZATION: '6d19d10c6b26c3eab28ee897e16319220488debdc0a3f62752f4d5516b16ede0',
    OBSERVER: 'd333215d6f6f8c18b9b36b14e908038bd9e1fcc0fe0fa8ed8a04204a4e9da49c',
    PROVENANCE: '11c0acd0bf014a1dd490c1b0be34cf1b70d9f8b20dd0be682e8639f177daeaa9',
}
# Independently pinned results of the reviewed observation-only transformations.
REBASED = {
    RUNTIME: '8a4b725280bbcd4f29b335368f41ee3f3ebbf00ffa28748337e752e9a9c07ffb',
    AUTHORIZATION: 'e0961262d5c098444a9a734d8f32c4058185e2f4043b68b0639e5091dd460c8b',
    OBSERVER: '95c6eb02327495cf596081584e1b1d5d11ac9da29f4dd5bfcfa4c2a42e3816bf',
    PROVENANCE: 'f2b32c12484a722c4b1b92f47f014407743facb6758e82a0539e9b2a4fd858e2',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


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
    expected = CURRENT.get(name, entry.get('current_before_sha256', entry['before_sha256']))
    if actual != expected:
        raise ValueError('Exact current source-copy base differs: ' + name)
    output, delta = registry.content(entry['sha256']), None
    strategy = 'central-declared-output'
    if name in (RUNTIME, AUTHORIZATION) and profile_name == 'traefik-native':
        output, strategy = original, 'current-product-preserved'
    elif name in CURRENT:
        output, delta = observation_delta(central, registry.content(entry['before_sha256']), output, original)
        strategy = 'sealed-observation-rebased-on-current-product'
    if name in CURRENT and profile_name == 'traefik-forwardauth' and digest(output) != REBASED.get(name):
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
    if profile_name == 'traefik-forwardauth':
        original = central.plain(target / PROVENANCE)
        if digest(original) != CURRENT[PROVENANCE]:
            raise ValueError('Exact current provenance source differs')
        output, delta = provenance_observation(central, original)
        if digest(output) != REBASED.get(PROVENANCE):
            raise ValueError('Pinned provenance observation output differs')
        inputs[PROVENANCE] = digest(original)
        transformations[PROVENANCE] = {'strategy': 'current-provenance-context-observation',
            'input_sha256': digest(original), 'output_sha256': digest(output),
            'applied_delta_sha256': digest(delta)}
        writes.append((target / PROVENANCE, output, 420))
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
