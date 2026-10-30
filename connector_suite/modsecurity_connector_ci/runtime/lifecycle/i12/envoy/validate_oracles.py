#!/usr/bin/env python3
"""Validate Envoy source proposals without changing canonical oracle results."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.evidence_io as evidence_io

REPOSITORY = connector_root()
STORAGE_ROOTS = tuple(root for root in evidence_io.DEFAULT_ROOTS if root != REPOSITORY)
ROUTES = {'envoy-ext-proc': (117, 51), 'envoy-ext-authz-request': (94, 40),
          'envoy-ext-authz-response-companion': (73, 34)}
CATEGORIES = {'SOURCE_SEMANTICS_CONFIRMED', 'FIXTURE_PENDING', 'OPEN'}
MAX_REFERENCE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
SUPPLEMENT_SCHEMA = 'i12.envoy.oracle-supplement.v1'
SUPPLEMENT_ROUTE = 'envoy-ext-authz-response-companion'
SUPPLEMENT_ID = 'I12::' + SUPPLEMENT_ROUTE + '::NEED-allow'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def reference_path(reference, source_root=None):
    if not isinstance(reference, dict) or not isinstance(reference.get('path'), str):
        raise ValueError('reference requires a path and SHA256')
    value = reference['path']
    path = Path(value)
    candidates = None
    if not value or '\\' in value or '..' in path.parts:
        raise ValueError('reference path traversal is forbidden')
    if path.is_absolute():
        if not any(root in path.parents for root in STORAGE_ROOTS):
            raise ValueError('absolute reference outside approved storage: ' + value)
        candidates = [path]
    else:
        candidates = source_candidates(path, source_root)
    expected = reference.get('sha256')
    if not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('reference requires a lowercase SHA256: ' + value)
    return value, candidates, expected


def source_candidates(path, source_root):
    if any(part in ('.git', '.aws', '.codex', '.agents') for part in path.parts):
        raise ValueError('reference is not a product source path')
    candidates = [REPOSITORY / path]
    if source_root is not None:
        root = Path(source_root)
        if not root.is_absolute() or '..' in root.parts:
            raise ValueError('historical source root must be absolute without traversal')
        historical = root / path
        if historical != candidates[0]:
            candidates.append(historical)
    return candidates


def source_fields(reference, cached, size, value):
    if size > MAX_SOURCE_BYTES:
        raise ValueError('source reference exceeds line-check bound: ' + value)
    line = reference.get('line')
    if type(line) is not int or not 1 <= line <= cached['line_count']:
        raise ValueError('source reference line outside file: ' + value)
    if not isinstance(reference.get('symbol'), str) or not reference['symbol']:
        raise ValueError('source reference requires a symbol: ' + value)
    if not isinstance(reference.get('claim'), str) or not reference['claim']:
        raise ValueError('source reference requires a claim: ' + value)
    return {'line': line, 'symbol': reference['symbol'], 'claim': reference['claim']}


class References:
    def __init__(self, source_root=None):
        self.cache = {}
        self.source_root = source_root

    def check(self, reference, source=False):
        value, candidates, expected = reference_path(reference, self.source_root)
        selected = None
        for path in candidates:
            selected = self.match(path, expected, source, value)
            if selected is not None:
                break
        if selected is None:
            raise ValueError('reference SHA256 mismatch: ' + value)
        cached, size = selected
        if 'bytes' in reference and (type(reference['bytes']) is not int or reference['bytes'] != size):
            raise ValueError('reference byte size mismatch: ' + value)
        result = {'path': value, 'sha256': expected, 'bytes': size, 'verified': True}
        if source:
            result.update(source_fields(reference, cached, size, value))
        return result

    def match(self, path, expected, source, value):
        try:
            with evidence_io.open_evidence(path, (REPOSITORY, *STORAGE_ROOTS), MAX_REFERENCE_BYTES) as (stream, before):
                cached = self.cached_reference(path, stream, before)
                if cached['sha256'] != expected:
                    return None
                if source and 'line_count' not in cached:
                    if before.st_size > MAX_SOURCE_BYTES:
                        raise ValueError('source reference exceeds line-check bound: ' + value)
                    stream.seek(0)
                    cached['line_count'] = len(stream.read(MAX_SOURCE_BYTES + 1).splitlines())
                return cached, before.st_size
        except FileNotFoundError:
            return None

    def cached_reference(self, path, stream, before):
        identity = evidence_io.identity(before)
        cached = self.cache.get(path)
        if cached is None or cached['identity'] != identity:
            cached = {'identity': identity,
                      'sha256': evidence_io.digest_stream(stream, MAX_REFERENCE_BYTES),
                      'bytes': before.st_size}
            self.cache[path] = cached
        return cached

    def nested(self, value):
        result = []
        if isinstance(value, dict):
            if 'path' in value or 'sha256' in value:
                result.append(self.check(value))
            for child in value.values():
                result.extend(self.nested(child))
        elif isinstance(value, list):
            for child in value:
                result.extend(self.nested(child))
        # Preserve only reference metadata; never read payloads into the output.
        return result


def baseline_route(baseline_rows, route, total, count):
    all_rows = [row for row in baseline_rows if row.get('leg_id') == route]
    selected = [row for row in all_rows if row.get('original_oracle_member') is True]
    if len(all_rows) != total or len(selected) != count:
        raise ValueError('baseline route membership/count differs: ' + route)
    resolved = sum((row.get('oracle_review') or {}).get('resolved') is True for row in selected)
    passes = sum(row.get('qualified_host_lifecycle_pass') is True for row in all_rows)
    if resolved != 1 or passes != 1:
        raise ValueError('baseline canonical resolution/lifecycle count differs: ' + route)
    counts = {'resolved': resolved, 'open': count - resolved, 'lifecycle_pass': passes}
    members = {row['run_scoped_case_id']: row for row in selected}
    return members, counts


def baseline_contract(baseline):
    baseline_hash = None
    if not isinstance(baseline, dict):
        raw = evidence_io.read_bytes(baseline, (REPOSITORY, *STORAGE_ROOTS))
        baseline_hash = hashlib.sha256(raw).hexdigest()
        baseline = json.loads(raw)
    baseline_rows = baseline.get('rows')
    if not isinstance(baseline_rows, list) or len(baseline_rows) != 284:
        raise ValueError('baseline must retain exactly 284 original Envoy IDs')
    identifiers = [row.get('run_scoped_case_id') for row in baseline_rows]
    if len(set(identifiers)) != 284:
        raise ValueError('duplicate original baseline ID')
    originals = {}
    canonical_counts = {}
    for route, (total, count) in ROUTES.items():
        originals[route], canonical_counts[route] = baseline_route(baseline_rows, route, total, count)
    return baseline_rows, originals, canonical_counts, baseline_hash


def review_document(review_path, baseline_hash, by_route, originals, references):
    raw = evidence_io.read_bytes(review_path, (REPOSITORY, *STORAGE_ROOTS))
    document = json.loads(raw)
    route = document.get('route')
    if route not in ROUTES or route in by_route:
        raise ValueError('unknown or duplicate review route')
    if 'records' in document and 'rows' in document:
        raise ValueError('review has competing records/rows arrays')
    rows = document.get('records', document.get('rows'))
    if not isinstance(rows, list):
        raise ValueError('review requires records or rows')
    for flag in ('lifecycle_qualification_performed', 'canonical_oracle_inventory_changed'):
        if flag in document and document[flag] is not False:
            raise ValueError('source review cannot change lifecycle/canonical results')
    if document.get('summary', {}).get('new_lifecycle_pass', 0) != 0:
        raise ValueError('source review cannot invent lifecycle PASS')
    if baseline_hash is not None and document.get('baseline_sha256', baseline_hash) != baseline_hash:
        raise ValueError('review names a different baseline SHA256')
    document_refs = references.nested(document)
    ids = [row.get('run_scoped_case_id') for row in rows]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate reviewed original ID: ' + route)
    if set(ids) != set(originals[route]):
        raise ValueError('reviewed original-ID membership differs: ' + route)
    return route, rows, raw, document_refs


def source_only_row(row, identity):
    if row.get('lifecycle_qualified') is not False:
        raise ValueError('lifecycle_qualified must be explicitly false: ' + identity)
    for flag in ('full_lifecycle_qualified', 'host_lifecycle_qualified', 'qualified_host_lifecycle_pass',
                 'canonical_ledger_resolution_changed'):
        if flag in row and row[flag] is not False:
            raise ValueError('source row invents lifecycle/canonical result: ' + identity)
    if any(row.get(field) == 'PASS' for field in ('outcome', 'status', 'host_acceptance')):
        raise ValueError('source row cannot assign host PASS: ' + identity)


def row_identity(row, route, original, identity):
    if row.get('route') != route or not identity.startswith('I12::' + route + '::'):
        raise ValueError('review row route membership differs: ' + identity)
    if canonical(row.get('original_oracle')) != canonical(original['original_oracle']):
        raise ValueError('original oracle changed: ' + identity)
    source_only_row(row, identity)
    existing = (original.get('oracle_review') or {}).get('resolved') is True
    if 'existing_canonical_oracle_resolved' in row and row['existing_canonical_oracle_resolved'] is not existing:
        raise ValueError('existing canonical oracle flag changed: ' + identity)
    category = row.get('category')
    if category not in CATEGORIES:
        raise ValueError('unknown source-review category: ' + identity)
    return existing, category


def binding_identity(binding, identity, route):
    if not isinstance(binding, dict):
        raise ValueError('fixture binding must be an object: ' + identity)
    for field in ('original_id', 'run_scoped_case_id'):
        if field in binding and binding[field] != identity:
            raise ValueError('fixture binding names a different original ID: ' + identity)
    if 'route' in binding and binding['route'] != route:
        raise ValueError('fixture binding route differs: ' + identity)


def checked_fixture_binding(row, identity, route, references):
    binding = row.get('fixture_binding')
    checked_binding = []
    new_binding = False
    if binding is not None:
        binding_identity(binding, identity, route)
        checked_binding = references.nested(binding)
        if not checked_binding:
            raise ValueError('fixture binding has no physical references: ' + identity)
        new_binding = binding.get('origin') == 'new_task_fixture_binding'
        if new_binding:
            if not any(field in binding for field in ('original_id', 'run_scoped_case_id')):
                raise ValueError('new binding requires an explicit original ID: ' + identity)
    return binding, checked_binding, new_binding


def source_oracle(row, category, existing, new_binding, identity):
    effective = row.get('effective_oracle')
    if effective is not None and not isinstance(effective, dict):
        raise ValueError('effective oracle must be an object or null: ' + identity)
    oracle_ready = (category == 'SOURCE_SEMANTICS_CONFIRMED' and bool(effective)
                    and row.get('source_oracle_resolved', True) is True)
    if oracle_ready and not existing and not new_binding:
        raise ValueError('new source oracle lacks an explicit new fixture binding: ' + identity)
    if row.get('source_oracle_resolved') is True and not oracle_ready:
        raise ValueError('source_oracle_resolved contradicts category/effective oracle: ' + identity)
    return effective, oracle_ready


def retained_oracle_requirements(row, original, existing, effective, identity):
    canonical_effective = (original.get('oracle_review') or {}).get('effective_oracle')
    if existing and canonical_effective is not None and canonical(effective) != canonical(canonical_effective):
        raise ValueError('existing canonical effective oracle changed: ' + identity)
    remaining = row.get('remaining_requirements')
    if not isinstance(remaining, list) or not remaining or any(not isinstance(value, str) for value in remaining):
        raise ValueError('remaining host requirements must remain explicit: ' + identity)
    return canonical_effective, remaining


def review_route(rows, route, originals, canonical_counts, references, review_path):
    normalized = {}
    category_ids = {category: [] for category in sorted(CATEGORIES)}
    proposed, bindings, partial, boundary = [], [], [], []
    for row in rows:
        identity = row['run_scoped_case_id']
        original = originals[identity]
        existing, category = row_identity(row, route, original, identity)
        category_ids[category].append(identity)
        refs = row.get('source_refs')
        if not isinstance(refs, list) or not refs:
            raise ValueError('every original oracle needs source references: ' + identity)
        checked_source = [references.check(reference, source=True) for reference in refs]
        binding, checked_binding, new_binding = checked_fixture_binding(row, identity, route, references)
        if new_binding:
            bindings.append(identity)
        effective, oracle_ready = source_oracle(row, category, existing, new_binding, identity)
        if oracle_ready and not existing:
            proposed.append(identity)
        elif effective and not existing:
            partial.append(identity)
        elif category == 'SOURCE_SEMANTICS_CONFIRMED' and not existing:
            boundary.append(identity)
        canonical_effective, remaining = retained_oracle_requirements(row, original, existing, effective, identity)
        normalized[identity] = {'run_scoped_case_id': identity, 'route': route, 'category': category,
            'original_oracle': copy.deepcopy(original['original_oracle']),
            'canonical_oracle_resolved': existing, 'canonical_effective_oracle': copy.deepcopy(canonical_effective),
            'effective_source_proposal': copy.deepcopy(effective),
            'proposed_new_source_oracle': identity in proposed,
            'source_refs': checked_source,
            'fixture_binding': None if binding is None else {'origin': binding.get('origin'),
                'original_id': identity, 'references': checked_binding},
            'remaining_requirements': list(remaining), 'lifecycle_qualified': False,
            'canonical_resolution_changed': False, 'review_file': str(review_path)}
    counts = {'original_count': len(originals), 'reviewed_count': len(rows),
        'canonical_resolved': canonical_counts['resolved'], 'canonical_open': canonical_counts['open'],
        'existing_lifecycle_pass': canonical_counts['lifecycle_pass'],
        'proposed_new_source_oracles': len(proposed), 'proposed_new_source_oracle_ids': sorted(proposed),
        'new_fixture_binding_ids': sorted(bindings), 'partial_oracle_proposal_ids': sorted(partial),
        'source_boundary_only_ids': sorted(boundary),
        'categories': {key: len(value) for key, value in category_ids.items()},
        'category_ids': {key: sorted(value) for key, value in category_ids.items()}}
    return normalized, counts


def validate(baseline, review_paths, source_root=None):
    """Return normalized proposal metadata; canonical 3/122 remains unchanged.

    ``baseline`` accepts a parsed baseline object or its physical JSON path.
    Review paths must contain exactly one complete review for each Envoy route.
    Raises ValueError/OSError on a contract, identity or physical integrity gap.
    """
    baseline_rows, originals, canonical_counts, baseline_hash = baseline_contract(baseline)
    references = References(source_root)
    documents, normalized, by_route = [], {}, {}
    for review_path in review_paths:
        review_path = Path(review_path)
        route, rows, raw, document_refs = review_document(
            review_path, baseline_hash, by_route, originals, references)
        route_rows, by_route[route] = review_route(
            rows, route, originals[route], canonical_counts[route], references, review_path)
        normalized.update(route_rows)
        documents.append({'path': str(review_path), 'sha256': hashlib.sha256(raw).hexdigest(),
                          'physical_reference_occurrences_verified': len(document_refs)})
    if set(by_route) != set(ROUTES) or len(normalized) != 125:
        raise ValueError('all three complete route reviews and all 125 original oracles are required')
    return {'schema': 'i12.envoy.validated-source-proposals.v1', 'baseline_total_ids': 284,
        'original_count': 125, 'reviewed_count': len(normalized),
        'canonical_resolved': 3, 'canonical_open': 122, 'existing_lifecycle_pass': 3,
        'canonical_resolution_changed': False, 'new_lifecycle_pass': 0,
        'proposal_scope': 'Source proposals only; canonical oracle resolution and host qualification are unchanged.',
        'proposed_new_source_oracles': sum(value['proposed_new_source_oracles'] for value in by_route.values()),
        'routes': by_route, 'input_reviews': documents,
        'normalized_rows': [normalized[row['run_scoped_case_id']] for row in baseline_rows
                            if row.get('original_oracle_member') is True]}


def checked_review_file(path):
    raw = evidence_io.read_bytes(path, (REPOSITORY, *STORAGE_ROOTS))
    return json.loads(raw), {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def supplement_row(document):
    if document.get('schema') != SUPPLEMENT_SCHEMA or document.get('route') != SUPPLEMENT_ROUTE:
        raise ValueError('unknown supplement schema or route')
    if 'records' in document and 'rows' in document:
        raise ValueError('supplement has competing records/rows arrays')
    rows = document.get('records', document.get('rows'))
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError('supplement requires exactly one original row')
    row = rows[0]
    if row.get('run_scoped_case_id') != SUPPLEMENT_ID or row.get('route') != SUPPLEMENT_ROUTE:
        raise ValueError('supplement original ID or route is not selected')
    source_only_row(row, SUPPLEMENT_ID)
    if row.get('category') != 'SOURCE_SEMANTICS_CONFIRMED':
        raise ValueError('supplement requires confirmed source semantics')
    return row


def source_review_context(validated):
    if (validated.get('schema') != 'i12.envoy.validated-source-proposals.v1'
            or validated.get('reviewed_count') != 125 or validated.get('original_count') != 125
            or validated.get('canonical_resolution_changed') is not False or validated.get('new_lifecycle_pass') != 0):
        raise ValueError('supplement requires a complete source-only validation')
    rows = validated.get('normalized_rows', [])
    if len(rows) != 125 or len({row['run_scoped_case_id'] for row in rows}) != 125:
        raise ValueError('supplement requires all 125 unique normalized originals')
    selected = [row for row in rows if row['run_scoped_case_id'] == SUPPLEMENT_ID]
    if len(selected) != 1 or selected[0].get('route') != SUPPLEMENT_ROUTE:
        raise ValueError('supplement original absent from validated inventory')
    return selected[0]


def supplement_origin(document, validated, prior):
    origin = document.get('origin_review')
    if not isinstance(origin, dict) or not isinstance(origin.get('path'), str):
        raise ValueError('supplement requires a physical origin review')
    path = Path(origin['path'])
    if not path.is_absolute() or str(path) != prior['review_file']:
        raise ValueError('supplement origin differs from normalized source review')
    inputs = [item for item in validated.get('input_reviews', []) if item['path'] == str(path)]
    if len(inputs) != 1 or inputs[0]['sha256'] != origin.get('sha256'):
        raise ValueError('supplement origin differs from validated input review')
    old_document, actual = checked_review_file(path)
    if type(origin.get('bytes')) is not int or canonical(origin) != canonical(actual):
        raise ValueError('supplement origin physical identity mismatch')
    return old_document, actual


def supplement_source_flags(document):
    for flag in ('lifecycle_qualification_performed', 'canonical_oracle_inventory_changed',
                 'canonical_resolution_changed', 'full_lifecycle_qualified', 'host_lifecycle_qualified',
                 'lifecycle_qualified', 'qualified_host_lifecycle_pass', 'canonical_ledger_resolution_changed'):
        if flag in document and document[flag] is not False:
            raise ValueError('supplement cannot change lifecycle/canonical results')
    if document.get('new_lifecycle_pass', 0) != 0 or document.get('summary', {}).get('new_lifecycle_pass', 0) != 0:
        raise ValueError('supplement cannot invent lifecycle PASS')
    if any(document.get(field) == 'PASS' for field in ('outcome', 'status', 'host_acceptance')):
        raise ValueError('supplement cannot assign host PASS')


def normalized_supplement_row(row, prior, validated, references, review_path):
    original = {'original_oracle': prior['original_oracle'], 'oracle_review': {
        'resolved': prior['canonical_oracle_resolved'], 'effective_oracle': prior['canonical_effective_oracle']}}
    route_counts = validated['routes'][SUPPLEMENT_ROUTE]
    counts = {'resolved': route_counts['canonical_resolved'], 'open': route_counts['canonical_open'],
              'lifecycle_pass': route_counts['existing_lifecycle_pass']}
    rows, _ = review_route([row], SUPPLEMENT_ROUTE, {SUPPLEMENT_ID: original}, counts, references, review_path)
    return rows[SUPPLEMENT_ID]


def unchanged_supplement_source(current, prior):
    for field in ('route', 'category', 'original_oracle', 'canonical_oracle_resolved', 'canonical_effective_oracle',
                  'effective_source_proposal', 'source_refs', 'lifecycle_qualified', 'canonical_resolution_changed'):
        if canonical(current[field]) != canonical(prior[field]):
            raise ValueError('supplement changed source semantics: ' + field)


def fixture_reference_named(references, suffix):
    selected = [ref for ref in references if Path(ref['path']).name.endswith(suffix)]
    if len(selected) != 1:
        raise ValueError('supplement fixture requires one ' + suffix)
    return selected[0]


def referenced_document(reference):
    document, actual = checked_review_file(Path(reference['path']))
    if any(reference.get(field) != actual[field] for field in ('path', 'sha256', 'bytes')):
        raise ValueError('supplement physical reference changed while validating')
    return document


def supplement_fixture_ledger(checked, shape_ref):
    ledger_ref = fixture_reference_named(checked, '-ledger.json')
    ledger = referenced_document(ledger_ref)
    members = ledger.get('files')
    if not isinstance(members, dict) or not members or 'shape.json' not in members:
        raise ValueError('supplement fixture ledger requires complete members')
    directory = Path(shape_ref['path']).parent
    by_path = {ref['path']: ref for ref in checked}
    for name, digest in members.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or not relative.parts or '\\' in name:
            raise ValueError('supplement fixture ledger member outside fixture')
        ref = by_path.get(str(directory / relative))
        if ref is None or ref['sha256'] != digest:
            raise ValueError('supplement fixture ledger member missing or changed')
    return ledger_ref, directory


def supplement_fixture_binding(row, references):
    binding = row.get('fixture_binding')
    if (not isinstance(binding, dict) or binding.get('origin') != 'new_task_fixture_binding'
            or binding.get('original_id') != SUPPLEMENT_ID or not isinstance(binding.get('files'), list)):
        raise ValueError('supplement requires an explicit new original fixture binding')
    checked = [references.check(ref) for ref in binding['files']]
    if len({ref['path'] for ref in checked}) != len(checked):
        raise ValueError('supplement fixture duplicates a physical file')
    shape_ref = fixture_reference_named(checked, 'shape.json')
    shape = referenced_document(shape_ref)
    if (shape.get('leg') != SUPPLEMENT_ROUTE
            or shape.get('original_case_ids', [SUPPLEMENT_ID]) != [SUPPLEMENT_ID]):
        raise ValueError('supplement fixture shape identity differs')
    ledger_ref, directory = supplement_fixture_ledger(checked, shape_ref)
    admission_ref = fixture_reference_named(checked, '-admission.json')
    admission = referenced_document(admission_ref)
    fixtures = [item for item in admission.get('bindings', []) if item.get('target') == '/mnt/fixtures']
    expected = {'source': str(directory), 'ledger': ledger_ref['path'], 'ledger_sha256': ledger_ref['sha256']}
    if len(fixtures) != 1 or any(fixtures[0].get(key) != value for key, value in expected.items()):
        raise ValueError('supplement admission fixture binding differs')


def validate_supplement(path, validated_source_review, source_root=None):
    """Validate the one Companion retake fixture without assigning host acceptance."""
    document, review_file = checked_review_file(Path(path))
    supplement_source_flags(document)
    row = supplement_row(document)
    prior = source_review_context(validated_source_review)
    old_document, origin = supplement_origin(document, validated_source_review, prior)
    old_rows = old_document.get('records', old_document.get('rows', []))
    originals = [item for item in old_rows if item.get('run_scoped_case_id') == SUPPLEMENT_ID]
    if len(originals) != 1:
        raise ValueError('supplement origin requires one matching original')
    references = References(source_root)
    old_normal = normalized_supplement_row(originals[0], prior, validated_source_review, references, origin['path'])
    if canonical(old_normal) != canonical(prior):
        raise ValueError('supplement origin no longer matches fresh normalized validation')
    normalized = normalized_supplement_row(row, prior, validated_source_review, references, path)
    unchanged_supplement_source(normalized, old_normal)
    supplement_fixture_binding(row, references)
    return {'schema': 'i12.envoy.validated-oracle-supplement.v1', 'route': SUPPLEMENT_ROUTE,
        'original_id': SUPPLEMENT_ID, 'review_file': review_file, 'origin_review': origin,
        'normalized_rows': [normalized], 'canonical_resolution_changed': False, 'new_lifecycle_pass': 0}


def main():
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.qualify_originals as qualify_originals

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--review', type=Path, action='append', required=True)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.baseline, args.review, args.source_root)
    qualify_originals.write(args.output, result)
    print(json.dumps({'original_count': result['original_count'], 'reviewed_count': result['reviewed_count'],
        'canonical_resolved': 3, 'canonical_open': 122,
        'proposed_new_source_oracles': result['proposed_new_source_oracles'], 'new_lifecycle_pass': 0}))


if __name__ == '__main__':
    main()
