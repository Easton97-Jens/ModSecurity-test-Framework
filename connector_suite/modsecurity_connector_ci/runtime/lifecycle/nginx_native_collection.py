"""Collect closed native references, never validate or promote runtime proof."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import copy
import importlib.util
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent


def _load(_name, filename):
    module = load_source(HERE / filename)
    return module


SOURCE = _load('native_collection_source', 'nginx-native-operation-source.py')
DISPATCH = _load('native_collection_dispatch', 'run-selected-nginx-native-operations.py')
FIELDS = frozenset({'schema_version', 'case_id', 'run_id', 'operation', 'integration_mode',
                    'bundle_root', 'source_sha256', 'invocations'})
OUTER = ('case_id', 'run_id', 'connector', 'operation', 'integration_mode', 'status',
         'canonical_status', 'parent_sha', 'framework_sha', 'mrts_sha',
         'parent_framework_gitlink', 'driver_exit_code', 'native_operation_receipt')
SOURCE_RESULT = 'source-result.json'


def _text(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def authority_directory(path):
    """Caller authority is external, existing, owned, safe and never a checkout."""
    if path is None:
        raise ValueError('native collection requires explicit caller authority')
    path = Path(path)
    if (not path.is_absolute() or '..' in path.parts or SOURCE.STORAGE not in path.parents
            or 'worktrees' in path.parts or '.git' in path.parts or len(str(path)) > 4096):
        raise ValueError('native authority must be an external storage child, not a checkout')
    current = SOURCE.STORAGE
    for part in path.relative_to(SOURCE.STORAGE).parts:
        current /= part
        descriptor = SOURCE.directory(current)
        try:
            try:
                os.stat('.git', dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('native authority cannot contain a checkout')
        finally:
            os.close(descriptor)
    return path


def _sealed_leaf(root, path, seal):
    if not _text(seal, r'[0-9a-f]{64}'):
        raise ValueError('native receipt requires exact SHA256')
    raw = SOURCE.read_owned(root, path)
    if SOURCE.digest(raw) != seal:
        raise ValueError('native original receipt differs from its source seal')


def validate_outer_identity(row, connector, expectations):
    case = row.get('case_id')
    contract = DISPATCH.CONTRACTS.get(case) if isinstance(case, str) else None
    if connector != 'nginx' or row.get('connector') != connector or case not in expectations or contract is None:
        raise ValueError('native collection requires an exact selected NGINX case')
    if (row.get('operation') != contract['operation'] or row.get('integration_mode') != SOURCE.MODE
            or not _text(row.get('run_id'), r'[A-Za-z0-9_-]{1,96}')
            or row.get('status') != 'NOT_EXECUTED' or row.get('canonical_status') != 'NOT_EXECUTED'
            or type(row.get('driver_exit_code')) is not int):
        raise ValueError('native source identity/status/actual driver exit is invalid')
    if any(not _text(row.get(key), r'[0-9a-f]{40}') for key in
           ('parent_sha', 'framework_sha', 'mrts_sha', 'parent_framework_gitlink')):
        raise ValueError('native source requires exact Git revisions')
    return case, contract


def validate_wrapper_identity(row, case, contract):
    wrapper = row.get('native_operation_receipt')
    extra = {'source_record_id'} if case in SOURCE.ALIASES else set()
    event = contract['operation'] == 'native_event_boundary_request'
    if event:
        extra |= {'parent_receipt_path', 'parent_receipt_sha256'}
    if not isinstance(wrapper, dict) or set(wrapper) != FIELDS | extra:
        raise ValueError('native wrapper has missing or unknown fields')
    if (type(wrapper['schema_version']) is not int or wrapper['schema_version'] != 1
            or any(wrapper[key] != row[key] for key in ('case_id', 'run_id', 'operation', 'integration_mode'))
            or (case in SOURCE.ALIASES and wrapper['source_record_id'] != SOURCE.ALIASES[case])):
        raise ValueError('native wrapper identity differs from source')
    return wrapper, event


def validate_source_seals(hashes):
    if (not isinstance(hashes, dict) or not 1 <= len(hashes) <= 128
            or any(not _text(name, r'(?:parent|framework):[A-Za-z0-9_./-]{1,512}')
                   or any(part in ('', '.', '..') for part in name.partition(':')[2].split('/'))
                   or not _text(value, r'[0-9a-f]{64}') for name, value in hashes.items())):
        raise ValueError('native source seals must be bounded namespaced paths')


def expected_invocations(bundle, wrapper, case, contract, event):
    if event:
        expected = [('at', 'at255/' + SOURCE_RESULT), ('over', 'over256/' + SOURCE_RESULT)] if case == 'event_json_limit' else [('main', 'long-query/' + SOURCE_RESULT)]
        if wrapper['parent_receipt_path'] != SOURCE_RESULT:
            raise ValueError('event parent receipt path is not closed')
        _sealed_leaf(bundle, wrapper['parent_receipt_path'], wrapper['parent_receipt_sha256'])
        return expected
    leaves = {'native_h1_parser_rejection': SOURCE_RESULT, 'native_phase4_request': SOURCE_RESULT,
              'request_sequence': 'sequence-source.json', 'common_mapper_input_fault': 'input-fault-source.json'}
    return [('main', leaves[contract['operation']])]


def validate_invocations(bundle, invocations, expected):
    if not isinstance(invocations, list) or len(invocations) != len(expected):
        raise ValueError('native invocation list is not closed')
    for invocation, (name, path) in zip(invocations, expected, strict=True):
        if (not isinstance(invocation, dict) or set(invocation) != {'name', 'receipt_path', 'receipt_sha256'}
                or invocation['name'] != name or invocation['receipt_path'] != path):
            raise ValueError('native invocation identity/path is not closed')
        _sealed_leaf(bundle, path, invocation['receipt_sha256'])


def collect_native_row(row, connector, expectations, allowed_root):
    """Check reference safety only; original proof belongs to Framework reader."""
    authority = authority_directory(allowed_root)
    case, contract = validate_outer_identity(row, connector, expectations)
    wrapper, event = validate_wrapper_identity(row, case, contract)
    reference = wrapper['bundle_root']
    if not isinstance(reference, str) or len(reference) > 4096:
        raise ValueError('native bundle reference is not bounded')
    bundle = Path(reference)
    if not bundle.is_absolute() or authority not in bundle.parents or '..' in bundle.parts:
        raise ValueError('native bundle must be strictly beneath caller authority')
    authority_directory(bundle)
    validate_source_seals(wrapper['source_sha256'])
    expected = expected_invocations(bundle, wrapper, case, contract, event)
    validate_invocations(bundle, wrapper['invocations'], expected)
    result = {key: copy.deepcopy(row[key]) for key in OUTER}
    if row['driver_exit_code'] != 0:
        result['status'] = 'FAIL'
        result['canonical_status'] = 'FAIL'
    return result
