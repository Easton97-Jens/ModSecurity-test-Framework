#!/usr/bin/env python3
"""Prepare distinct original Stock I12 fixtures using the retained capture ABI.

This extends the existing approved lighttpd launcher/client/backend sources.
It writes no verdict. Original selected contracts and null expectations remain
intact beside independently specified fixture expectations before execution.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys

_I12_LIBRARY = source_path('ci') / 'lib'

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths
try:
    from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.qualification import EXTERNAL_ROOT, storage_root
except ModuleNotFoundError:
    from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.qualification import EXTERNAL_ROOT, storage_root

ADMISSION_SPEC_FILE = 'admission-spec.json'
ARTIFACT_LEDGER_FILE = 'artifacts-ledger.json'
BACKEND_LAUNCHER_FILE = 'backend-launch.py'
BACKEND_OBSERVER_FILE = 'observed-backend.py'
CLIENT_FILE = 'curl-raw-client.py'
CSV_MIME = 'text/csv'
DEFAULT_ERROR_STATUS = 'default_error_status=502'
DEFAULT_TIMEOUT_ARGUMENTS = "'--timeout-ms','3000'"
ENVIRONMENT_PREFIX = 'env={**os.environ,'
FIXTURE_CONTRACT_FILE = 'fixture-contract.json'
FIXTURE_PREFIX = '/mnt/fixtures/'
FULL_LIFECYCLE_PREFIX = 'full-lifecycle/'
LAUNCHER_FILE = 'launch.py'
MAIN_ARGUMENTS = "if label=='main':argv+="
NEIGHBOR_CALL = "    client('neighbor','GET'"
POST_ARGUMENTS = "if method=='POST':argv+="
POST_ARGUMENTS_LINE = "\n    if method=='POST':argv+="
PRIVATE_RULES_MODE = 'rules.chmod(0o600)'
PRIVATE_RUNTIME_MODE = 'runtime.chmod(0o600)'
STOCK_PATH_PREFIX = '/i12/stock/'
TASK_PREFIX = '/task/'


REPO = connector_root()
EXTERNAL = EXTERNAL_ROOT
PREVIOUS = EXTERNAL / 'runs/i12-lighttpd-410-20261015'
OLD = EXTERNAL / 'runs/e2e/20261014T182400Z-pr410-oracle-lifecycle'
MARKER = b'i12-request-marker'
RESPONSE = b'apx-eos-response-payload'
FRAMEWORK = OLD / 'sealed-common-inputs/framework'
CANONICAL_YAML_CASES = frozenset({'allow_without_marker', 'transaction_id_present',
    'transaction_id_generated_or_fallback', 'multiple_headers', 'duplicate_header_names',
    'empty_header_value', 'log_only', 'deny_header_marker_403',
    'deny_with_alternative_status', 'case_insensitive_header_name',
    'deny_request_body_marker_403', 'redirect_if_supported'})
CANONICAL_MIME_CASES = frozenset({'phase4_in_scope_content_type',
    'phase4_content_type_with_charset', 'phase4_out_of_scope_content_type',
    'phase4_missing_content_type'})
CANONICAL_METADATA_CASES = frozenset({'event_contains_connector', 'event_contains_transaction_id',
    'event_contains_rule_id', 'event_contains_phase', 'event_contains_status'})
CANONICAL_RESPONSE_HEADER_CASES = frozenset({'phase3_deny_before_commit',
    'phase3_redirect_before_commit', 'phase3_original_and_visible_status',
    'deny_response_header_marker_403'})
CONFIGURATION_CASES = frozenset({'valid_rules_file', 'missing_rules_file',
    'invalid_rule_syntax', 'unknown_config_key', 'invalid_boolean', 'invalid_status',
    'invalid_size', 'unsafe_event_path'})
CANONICAL_LIMIT_CASES = frozenset({'phase2_at_limit', 'phase2_over_limit', 'phase2_truncated',
    'phase4_body_at_limit', 'phase4_body_over_limit', 'phase4_body_process_partial', 'phase4_body_reject'})
CANONICAL_CHUNK_CASES = frozenset({'phase2_marker_split_across_chunks', 'phase4_marker_split_across_chunks'})
CANONICAL_LATE_CASES = frozenset({'phase4_rule_observed', 'phase4_deny_after_commit_log_only',
    'phase4_deny_after_commit_abort', 'phase4_event_contains_original_status',
    'phase4_event_contains_late_intervention_action', 'phase4_deny_after_commit_log_only_minimal',
    'phase4_deny_after_commit_log_only_safe', 'phase4_deny_after_commit_abort_strict',
    'phase4_strict_http1_client_abort', 'phase4_strict_host_survives',
    'phase4_strict_followup_request_succeeds', 'event_has_no_response_body_payload'})
MAPPING_CASES = frozenset({'header_count_at_limit', 'header_count_over_limit',
    'total_header_bytes_at_limit', 'total_header_bytes_over_limit', 'invalid_content_length',
    'conflicting_content_length', 'duplicate_transfer_encoding', 'content_length_overflow'})
CANONICAL_REUSE_CASES = frozenset({'allow', 'deny', 'phase1_allow', 'phase1_deny_403',
    'phase1_alternative_status', 'phase1_redirect', 'phase1_transaction_id',
    'phase2_request_body_rule', 'phase2_no_payload_event', 'phase3_response_header_rule',
    'phase4_status_metadata', 'phase4_action_metadata', 'phase4_no_payload_event',
    'phase4_end_of_stream_evaluation', 'event_has_no_request_body_payload'})
CANONICAL_SEQUENCE_CASES = frozenset({'single_request_cleanup', 'multiple_sequential_requests',
    'clean_shutdown', 'transport_http11_content_length', 'transport_sequential_requests'})


def _read_root(path, *, image=False):
    path = Path(path).absolute()
    roots = (REPO, EXTERNAL)
    if image:
        roots += (Path('/usr/lib/x86_64-linux-gnu'),)
    if ('..' in path.parts
            or any(part in {'.git', '.codex', '.aws', '.ssh', '.gnupg'} for part in path.parts)
            or not any(path != root and path.is_relative_to(root) for root in roots)):
        raise ValueError('input outside declared capture/source/library roots')
    if path.is_relative_to(EXTERNAL):
        storage_root(EXTERNAL)
    return path


def sha(path):
    path = regular(path, image=True)
    return hashlib.sha256(i12_paths._read_admitted(path, i12_paths.MAXIMUM_BYTES)).hexdigest()


def regular(path, *, image=False):
    # Authorize the lexical root before any filesystem probe of the input.
    path = _read_root(path, image=image)
    if any(part.is_symlink() for part in (*path.parents, path)):
        raise ValueError('source alias forbidden')
    detail = path.stat()
    if not stat.S_ISREG(detail.st_mode) or detail.st_nlink != 1:
        raise ValueError('source requires one regular file link')
    return path


def read_text(path):
    return i12_paths._read_admitted(regular(path), i12_paths.MAXIMUM_BYTES).decode('utf-8')


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    return sha(path)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('retained source boundary differs: ' + old[:80])
    return text.replace(old, new)


def response_helper_text():
    """Losslessly reuse the existing lighttpd capture's pure HTTP decoder."""
    source = regular(REPO / 'ci/runtime/lifecycle/i12/lighttpd/patched_qualification.py').read_text()
    nodes = ast.parse(source).body
    pieces = []
    for name in ('digest', 'decode_chunked_entity', 'response_decode'):
        matches = [node for node in nodes if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(matches) != 1:
            raise ValueError('existing lighttpd response helper contract changed')
        pieces.append(ast.get_source_segment(source, matches[0]))
    return 'import hashlib\n\n' + '\n\n'.join(pieces) + '\n'


def retain_http_after_transport_error(client):
    """Decode received HTTP bytes while retaining the independent socket error."""
    start = client.index("    header,encoded_body=bytes(received).split")
    end = client.index('\nexcept ConnectionResetError', start)
    decoder = client[start:end]
    decoder = replace_once(decoder, '    exit_code=0', "    if receipt['error'] is None:exit_code=0")
    decoder = '\n'.join('        ' + line for line in decoder.splitlines())
    client = client[:start] + client[end:]
    return replace_once(client, 'finally:\n    (root/',
        "finally:\n    if received:\n        try:\n" + decoder +
        "\n        except Exception as parse_error:\n            receipt['http_parse_error']={'type':type(parse_error).__name__,'message':str(parse_error)}\n    (root/")


def add_backend_header_boundary(source):
    """Observe actual parsed upstream headers before any backend body read."""
    source = replace_once(source, '"request_version": handler.request_version,',
        '"request_version": handler.request_version,\n              "boundary": getattr(handler, "_i12_capture_boundary", "body_consumed"),')
    return replace_once(source, '    def do_GET(self) -> None:', '''    def parse_request(self):
        accepted = super().parse_request()
        if accepted:
            self._i12_capture_boundary = 'headers_parsed'
            _apache_lifecycle_capture(self, b'')
            self._i12_capture_boundary = 'body_consumed'
        return accepted

    def do_GET(self) -> None:''')


def fixture(case):
    """Resolve a finite predeclared fixture without observing the target run."""
    for producer in (_remaining_normal_fixture, _configuration_fixture, _mapping_fixture, _timeout_fixture, _abort_fixture, _incomplete_fixture, _canonical_selected_fixture, _default_capacity_fixture, _sink_fixture, _pointer_fixture, _resource_fixture):
        value = producer(case)
        if value is not None:
            return value
    return _body_fixture(case)


def _remaining_normal_fixture(case):
    """Bind the remaining finite metadata and existing caller-fault controls."""
    if case in {'event_metadata_truncation', 'event_json_limit'}:
        value = canonical_fixture('log_only')
        value['canonical_rules'] = replace_once(value['canonical_rules'],
            "msg:'no-crs log-only'", "msg:'no-crs log-only " + 'metadata' * 512 + "'")
        value.update(case_id=case, preserve_original_oracle=True,
            metadata_generator_bytes=4096, configured_event_json_limit=512 if case == 'event_json_limit' else None,
            predicate_basis='Finite original long non-sensitive metadata generator on original phase1 rule1100402 and log-only request. Actual physical truncation remains to be measured; missing Common fields cannot be supplied from projections.')
        return value
    if case == 'full_lifecycle_event_metadata_bounded':
        value = canonical_fixture('phase4_body_over_limit')
        value.update(case_id=case, preserve_original_oracle=True,
            predicate_basis='Original catalog explicitly reuses phase4_body_over_limit. Exact own-ID host/client execution; required physical bounded metadata remains independently evaluated.')
        return value
    if case in {'early_mapping_failure_cleanup', 'transaction_begin_failure_cleanup', 'finish_failure_propagation'}:
        value = fixture('header_count_nonzero_with_null_headers' if case == 'early_mapping_failure_cleanup' else 'NEED-request-single-chunk')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, preserve_original_oracle=True)
        if case != 'early_mapping_failure_cleanup':
            value['diagnostic_boundary_fault'] = 'logging_error' if case == 'finish_failure_propagation' else 'request_headers_error'
            if case == 'transaction_begin_failure_cleanup':
                value.update(expected_visible_status=500, expected_backend_main_count=0,
                    expected_response_sha256=None, expected_response_finalizations=0)
        value['predicate_basis'] = 'Existing bounded actual Runtime caller/boundary fault after genuine HTTP input. SDK actual return is retained separately; actual cleanup/neighbor/status determine results, including committed response before logging failure.'
        return value
    return None


def _configuration_fixture(case):
    if case in CONFIGURATION_CASES:
        value = fixture('NEED-request-single-chunk')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, configuration_probe=case,
            predicate_basis='Actual delivered stock sidecar CLI/bootstrap parser and native SDK rules loader. Invalid startup exit78 and valid listener/start are separate from finite configtest exit0/1; no native-module -tt proxy.')
        return value


def _mapping_fixture(case):
    if case in MAPPING_CASES:
        value = fixture('NEED-request-single-chunk')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, mapping_probe=case,
            preserve_original_oracle=True, allow_main_transport_failure=True,
            predicate_basis='Exact configured64header/512name+value-byte boundary or finite malformedHTTP framing; actual raw request and actual runtime validation/native allocation scope remain separate.')
        if case not in {'header_count_at_limit', 'total_header_bytes_at_limit'}:
            value.update(expected_visible_status=400 if 'content_length' in case or 'transfer_encoding' in case else 500,
                expected_backend_main_count=0, expected_response_sha256=None, expected_response_finalizations=0)
        return value


def _timeout_fixture(case):
    if case == 'NEED-timeout':
        value = fixture('NEED-request-single-chunk')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, backend_delay_before_headers=True,
            expected_visible_status=504, expected_response_sha256=None,
            expected_response_finalizations=0,
            predicate_basis='Actual100ms Stock host deadline expires while actual backend delays500ms before response headers. No SDK timeout return is fabricated; native request admission and actual host timeout/cancel first cause remain separate.')
        return value


def _abort_fixture(case):
    if case in {'NEED-cancel', 'NEED-client-exit-signal', 'NEED-abort-reset-observation', 'NEED-rst-disconnect'}:
        value = fixture('NEED-request-single-chunk')
        mode = {'NEED-client-exit-signal': 'signal', 'NEED-cancel': 'close'}.get(case, 'reset')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, split_backend_response=True,
            response_hex=(RESPONSE + b'x' * 16384).hex(), backend_split_bytes=8192,
            client_abort_mode=mode, expected_client_exit=143 if mode=='signal' else 1,
            expected_response_sha256=None, expected_response_finalizations=0,
            predicate_basis='Independent client actually receives first5responsebytes then closes, requests SO_LINGER reset, or exits by actualSIGTERM. Peer reset/EOF are not inferred from local action; actual native EOS/cleanup and physical failure cause remain measured.')
        return value


def _incomplete_fixture(case):
    if case in {'NEED-missing-eos', 'NEED-incomplete-framing', 'NEED-first-byte-before-late-error'}:
        value = fixture('NEED-request-single-chunk')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case,
            backend_incomplete=True, expected_client_exit=1,
            expected_response_finalizations=0,
            predicate_basis='Actual backend declares five bytes beyond its finite body, flushes real payload, waits200ms and closes. Actual HTTP200/payload is retained with incomplete framing and client exit1; peer EOF does not imply host/native EOS.')
        if case == 'NEED-first-byte-before-late-error':
            body = RESPONSE + b'x' * 16384
            value.update(response_hex=body.hex(), expected_response_sha256=hashlib.sha256(body).hexdigest())
        return value


def _canonical_selected_fixture(case):
    if case in CANONICAL_YAML_CASES | CANONICAL_METADATA_CASES | CANONICAL_RESPONSE_HEADER_CASES | CANONICAL_MIME_CASES | CANONICAL_LIMIT_CASES | CANONICAL_CHUNK_CASES | CANONICAL_LATE_CASES | CANONICAL_REUSE_CASES | CANONICAL_SEQUENCE_CASES:
        return canonical_fixture(case)


def _default_capacity_fixture(case):
    if case == 'NEED-capacity-256m-reserve64m':
        value = fixture('NEED-resource-exhaustion-technical')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, default_capacity_probe=True,
            spool_capacity_bytes=268435456, spool_free_reserve_bytes=67108864,
            predicate_basis='Eight independent declared32MiB HTTP requests hold actual preallocations exhausting unchanged default256MiB; ninth4096-byte admission is technical503, close/readmit.64MiB reserve separately checked by unchanged product function at injected existing syscall seam.')
        return value


def _sink_fixture(case):
    if case.startswith('NEED-physical-event-sink-'):
        mode = case.removeprefix('NEED-physical-event-sink-')
        if mode not in ('open', 'write', 'short-write', 'flush', 'close'):
            raise ValueError('unsupported sink fault')
        value = fixture('NEED-request-single-chunk')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, sink_fault=mode,
            expected_visible_status=502, expected_backend_main_count=0,
            expected_response_sha256=None, expected_response_finalizations=0,
            predicate_basis='Test-only actual private event FILE I/O link fault; SDK decision and substituted stdio result remain separate; effective configured error response502 before backend admission.')
        if mode == 'close':
            value.update(expected_visible_status=200, expected_backend_main_count=1,
                expected_response_sha256=hashlib.sha256(RESPONSE).hexdigest(), expected_response_finalizations=1,
                predicate_basis='Complete benign host transaction and healthy neighbor precede test-only accept lifetime stop. Actual Runtime destroy calls realfclose, whose0result is separately recorded before injectedEOF; no request failure or SDK error is inferred from void Runtime destruction.')
        return value


def _pointer_fixture(case):
    if case in ('body_size_nonzero_with_null_data', 'header_count_nonzero_with_null_headers'):
        value = fixture('NEED-request-single-chunk')
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case,
            pointer_fault='body_null' if case.startswith('body_') else 'headers_null',
            expected_visible_status=500, expected_backend_main_count=0,
            expected_response_sha256=None, expected_response_finalizations=0,
            predicate_basis='Explicit test-only actual Runtime caller NULL pointer injection with nonzero count after genuine HTTP host input. Real Runtime validation return is preserved; no NULL wire format or SDK failure is claimed.')
        return value


def _resource_fixture(case):
    if case in ('NEED-resource-exhaustion-technical', 'NEED-readmission-after-release'):
        value = fixture('NEED-request-single-chunk')
        request = MARKER + b'x' * (4096 - len(MARKER))
        value.update(case_id=case, path=STOCK_PATH_PREFIX + case, request_hex=request.hex(),
            expected_request_sha256=hashlib.sha256(request).hexdigest(),
            expected_visible_status=503, expected_backend_main_count=0,
            expected_response_sha256=None, spool_capacity_bytes=8192,
            spool_free_reserve_bytes=4096, spool_probe=True,
            predicate_basis='4097-byte held preallocation plus distinct4096-byte request exceeds shared8192-byte technical capacity; native1MiB body limit remains unexceeded; closing holder permits readmission.')
        return value


REQUEST_VARIANT_CASES = frozenset(['NEED-request-streaming', 'NEED-request-file', 'NEED-request-content-type-missing', 'NEED-request-charset-present', 'NEED-request-csv', 'NEED-request-mime-scope-out', 'NEED-request-above-former-connector-limit', 'NEED-request-empty', 'NEED-request-marker-at-payload-end'])
RESPONSE_VARIANT_CASES = frozenset(['NEED-response-empty', 'NEED-response-streaming', 'NEED-response-file', 'NEED-response-above-former-connector-limit', 'NEED-response-csv', 'NEED-response-marker-at-payload-end'])


def _request_values(case):
    request, content_type, delayed = MARKER, "text/plain", False
    if case == 'NEED-request-streaming':
        request = b'a' * 4096 + MARKER + b'z' * 4096
        delayed = True
    elif case == 'NEED-request-file':
        request = (b'--i12-file-boundary\r\nContent-Disposition: form-data; name="payload"\r\n\r\n'
            + MARKER + b'\r\n--i12-file-boundary\r\nContent-Disposition: form-data; name="upload"; filename="body.txt"\r\nContent-Type: text/plain\r\n\r\n'
            + b'f' * 8192 + b'\r\n--i12-file-boundary--\r\n')
        content_type = 'multipart/form-data; boundary=i12-file-boundary'
        delayed = True
    elif case == 'NEED-request-content-type-missing':
        content_type = None
    elif case == 'NEED-request-charset-present':
        content_type = 'text/plain; charset=utf-8'
    elif case == 'NEED-request-csv':
        request = b'column,value\r\nfirst,i12-request-marker\r\n'
        content_type = CSV_MIME
    elif case == 'NEED-request-mime-scope-out':
        content_type = 'application/octet-stream'
    elif case == 'NEED-request-above-former-connector-limit':
        request = b'x' * (1048576 + 2048) + MARKER
    elif case == 'NEED-request-empty':
        request = b''
    elif case == 'NEED-request-marker-at-payload-end':
        request = b'x' * 8192 + MARKER
    return request, content_type, delayed


def _response_values(case):
    response, response_type = RESPONSE, "text/plain"
    if case == 'NEED-response-empty':
        response = b''
    elif case == 'NEED-response-streaming':
        response = b'a' * 8192 + RESPONSE
    elif case == 'NEED-response-file':
        response = b'f' * 8192 + RESPONSE
    elif case == 'NEED-response-above-former-connector-limit':
        response = b'x' * (1048576 + 2048) + RESPONSE
    elif case == 'NEED-response-csv':
        response = b'column,value\r\nfirst,apx-eos-response-payload\r\n'
        response_type = CSV_MIME
    elif case == 'NEED-response-marker-at-payload-end':
        response = b'x' * 8192 + RESPONSE
    return response, response_type


def _body_fixture(case):
    request, content_type, delayed = _request_values(case)
    response, response_type = _response_values(case)
    profile = "safe"
    if case.startswith('NEED-profile-'):
        profile = case.removeprefix('NEED-profile-')
        if profile not in ('all', 'off', 'safe', 'strict'):
            raise ValueError('unknown profile')
    elif case not in REQUEST_VARIANT_CASES | RESPONSE_VARIANT_CASES | {
        'NEED-request-single-chunk', 'NEED-request-content-type-present',
        'NEED-request-charset-missing', 'NEED-request-eos-once',
        'NEED-request-mime-scope-in',
        'NEED-response-single-chunk', 'NEED-response-charset-missing',
        'NEED-neighbor-connection-stream', 'NEED-private-spool-ready',
        'NEED-nonroot-uid', 'NEED-spool-ownership-0600-private0700',
        'NEED-capacity-256m-reserve64m', 'NEED-replay-only-after-native-p2-allow',
    }:
        raise ValueError('case needs a separately reviewed fixture: ' + case)
    live_spool = case in {'NEED-request-streaming', 'NEED-request-file',
        'NEED-private-spool-ready', 'NEED-spool-ownership-0600-private0700',
        'NEED-capacity-256m-reserve64m', 'NEED-replay-only-after-native-p2-allow'}
    if live_spool and case != 'NEED-request-file':
        request = MARKER + b'x' * 8192
        delayed = True
    result = {'case_id': case, 'method': 'POST', 'path': STOCK_PATH_PREFIX + case,
            'request_hex': request.hex(), 'response_hex': response.hex(),
            'request_content_type': content_type, 'response_content_type': response_type,
            'delayed_request': delayed, 'profile': profile,
            'sample_live_spool': live_spool,
            'request_body_source': 'materialized_regular_client_file',
            'expected_visible_status': 200, 'expected_backend_main_count': 1,
            'expected_native_request_finalizations': 1, 'expected_native_response_finalizations': 1,
            'expected_native_logging': 1, 'expected_native_cleanup': 1,
            'native_request_append_count': 0 if not request else None,
            'native_append_count_reason': 'zero body' if not request else 'actual chunk count must be measured, never derived from wire writes',
            'expected_request_sha256': hashlib.sha256(request).hexdigest(),
            'expected_response_sha256': hashlib.sha256(response).hexdigest(),
            'spool_capacity_bytes': 268435456, 'spool_free_reserve_bytes': 67108864,
            'predicate_basis': 'finite Content-Length, genuine native body access, pass/log marker rules, no disruptive rule',
            'expectations_created_before_execution': True}
    if case.startswith('NEED-profile-'):
        template = regular(REPO / 'examples/lighttpd/stock' / profile / 'msconnector-runtime.conf')
        arguments = regular(template.with_name('stock-sidecar.args'))
        result.update(profile_template={'path': str(template), 'sha256': sha(template)},
            profile_arguments={'path': str(arguments), 'sha256': sha(arguments)},
            profile_runtime_template=template.read_text())
    return result


def _reused_source_case(catalog, selected_contract):
    current = selected_contract
    for _step in range(8):
        source_case = current.get('deprecated_alias_for') or current.get('request', {}).get('reuses') or current['case_id']
        if (FRAMEWORK / 'tests/cases/no-crs-baseline' / (source_case + '.yaml')).is_file():
            break
        if source_case in CANONICAL_LATE_CASES:
            source_case = 'full-lifecycle/phase4_late_intervention'
            break
        if source_case in CANONICAL_CHUNK_CASES:
            source_case = FULL_LIFECYCLE_PREFIX + source_case
            break
        current = next(row for row in catalog if row['case_id'] == source_case)
    else:
        raise ValueError('original source reuse chain is unresolved')
    return source_case


def _canonical_source_case(case, catalog, selected_contract):
    if selected_contract.get('deprecated_alias_for') and case not in CANONICAL_REUSE_CASES:
        raise ValueError('deprecated aliases cannot inflate distinct canonical coverage')
    source_case = selected_contract['request']['reuses'] if case in CANONICAL_METADATA_CASES else case
    if case in CANONICAL_REUSE_CASES:
        source_case = _reused_source_case(catalog, selected_contract)
    if case in CANONICAL_SEQUENCE_CASES:
        source_case = 'full-lifecycle/transport' if case.startswith('transport_') else 'allow_without_marker'
    if case in CANONICAL_LIMIT_CASES:
        source_case = FULL_LIFECYCLE_PREFIX + ('phase2_body_limits' if case.startswith('phase2_') else 'phase4_body_limits')
    if case in CANONICAL_CHUNK_CASES:
        source_case = FULL_LIFECYCLE_PREFIX + case
    if case in CANONICAL_LATE_CASES:
        source_case = 'full-lifecycle/phase4_late_intervention'
    if case in CANONICAL_RESPONSE_HEADER_CASES:
        source_case = FULL_LIFECYCLE_PREFIX + ('phase3_redirect_before_commit' if case == 'phase3_redirect_before_commit' else 'phase3_deny_before_commit')
    return source_case


def _limit_materialization(case, original, body, response):
    limit_rules = ''
    if case in CANONICAL_LIMIT_CASES:
        limit = original['full_lifecycle']['limit_bytes']
        size = limit if case.endswith('at_limit') else limit + 1
        partial = case in {'phase2_truncated', 'phase4_body_process_partial'}
        if case.startswith('phase2_'):
            body = (body + b'x' * size)[:size]
            limit_rules = '\nSecRequestBodyLimit ' + str(limit) + '\nSecRequestBodyNoFilesLimit ' + str(limit) + '\nSecRequestBodyLimitAction ' + ('ProcessPartial' if partial else 'Reject')
        else:
            response = (response + b'x' * size)[:size]
            limit_rules = '\nSecResponseBodyLimit ' + str(limit) + '\nSecResponseBodyLimitAction ' + ('ProcessPartial' if partial else 'Reject')
    return body, response, limit_rules


def _canonical_options(case, original, response, result):
    if case == 'phase2_marker_split_across_chunks':
        result.update(delayed_request=True, explicit_request_split_bytes=len(original['full_lifecycle']['request_chunks'][0].encode()))
    if case == 'phase4_marker_split_across_chunks':
        result['backend_split_bytes'] = len(original['full_lifecycle']['response_chunks'][0].encode())
    if case in CANONICAL_LATE_CASES:
        result['split_backend_response'] = True
        if 'abort' in case or 'strict' in case:
            result.update(profile='strict', expected_client_exit=1, allow_main_transport_failure=True)
        elif case.endswith('minimal'):
            result['profile'] = 'off'
            result['explicit_phase4_mode'] = 'minimal'
        result['expected_response_finalizations'] = 1
    if case in {'single_request_cleanup', 'multiple_sequential_requests', 'clean_shutdown'}:
        result.update(expected_visible_status=200, expected_backend_main_count=1,
            expected_response_finalizations=1, expected_response_sha256=hashlib.sha256(response).hexdigest())
    if case in {'multiple_sequential_requests', 'transport_sequential_requests'}:
        result['sequence_probe'] = 'allow-deny-allow' if case == 'multiple_sequential_requests' else 'allow-allow'
    if case == 'transport_http11_content_length':
        result['framing_probe'] = 'http11_content_length'
    return result


def canonical_fixture(case):
    """Materialize an original YAML, never an alias or a name-derived allow."""
    import yaml
    catalog_source = regular(FRAMEWORK / 'tests/cases/no-crs-baseline/catalog.json')
    catalog = json.loads(catalog_source.read_text())['cases']
    selected_contract = next(row for row in catalog if row['case_id'] == case)
    source_case = _canonical_source_case(case, catalog, selected_contract)
    source = regular(FRAMEWORK / 'tests/cases/no-crs-baseline' / (source_case + '.yaml'))
    rules_source = regular(FRAMEWORK / 'tests/rules/no-crs-baseline.conf')
    original = yaml.safe_load(source.read_text())
    request = original['request']
    if case == 'deny_response_header_marker_403':
        request = selected_contract['request']
    body = request.get('body', '').encode()
    headers = request.get('headers', {})
    if isinstance(headers, dict):
        headers = list(headers.items())
    else:
        headers = [(row['name'], row['value']) for row in headers]
    content_type = next((value for name, value in headers if name.lower() == 'content-type'), None)
    status = selected_contract['expected_status']
    if status is None:
        status = original.get('expect', {}).get('status')
    response = original.get('response', {}).get('body', RESPONSE.decode()).encode()
    response_headers = list(original.get('response', {}).get('headers', {}).items())
    body, response, limit_rules = _limit_materialization(case, original, body, response)
    result = {'case_id': case, 'method': request['method'], 'path': request['path'],
        'request_hex': body.hex(), 'response_hex': response.hex(),
        'request_content_type': content_type, 'response_content_type': original.get('response', {}).get('content_type', 'text/plain'),
        'request_headers': headers, 'canonical_rules': rules_source.read_text() + '\n' + original['rules'] + limit_rules,
        'canonical_source': {'path': str(source), 'sha256': sha(source)},
        'canonical_catalog_source': {'path': str(catalog_source), 'sha256': sha(catalog_source)},
        'original_distinct_catalog_predicate': selected_contract,
        'reused_request_fixture_source': source_case if source_case != case else None,
        'deprecated_original_alias_for': selected_contract.get('deprecated_alias_for'),
        'new_distinct_scenario_claimed': not bool(selected_contract.get('deprecated_alias_for')),
        'resolved_source_case': source_case,
        'canonical_rules_source': {'path': str(rules_source), 'sha256': sha(rules_source)},
        'original_yaml_required_capabilities': original.get('required_capabilities', []),
        'original_yaml_audit_expectation': original.get('expect', {}).get('audit_log'),
        'canonical_expected_rule_id': selected_contract.get('expected_rule_id'),
        'canonical_catalog_phase': selected_contract['phase'],
        'response_headers': response_headers,
        'split_backend_response': case in CANONICAL_MIME_CASES or case.startswith('phase4_'),
        'delayed_request': False, 'profile': 'safe', 'sample_live_spool': False,
        'expected_visible_status': status, 'expected_backend_main_count': 1 if status == 200 or selected_contract['phase'] >= 3 else 0,
        'expected_response_finalizations': 0 if status != 200 else 1,
        'expected_request_sha256': hashlib.sha256(body).hexdigest(),
        'expected_response_sha256': hashlib.sha256(response).hexdigest() if status == 200 else None,
        'predicate_basis': 'Original independently retained YAML request, exact rules and declared expectation.',
        'expectations_created_before_execution': True}
    return _canonical_options(case, original, response, result)


def seal_tree(tree, ledger):
    files = {str(path.relative_to(tree)): sha(regular(path))
             for path in tree.rglob('*') if path.is_file()}
    for path in tree.rglob('*'):
        if path.is_symlink():
            raise ValueError('sealed input contains alias')
        path.chmod(0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444)
    tree.chmod(0o555)
    save(ledger, {'files': files})
    ledger.chmod(0o444)
    return {'source': str(tree), 'ledger': str(ledger), 'ledger_sha256': sha(ledger)}


def add_live_sampler(launch):
    launch = replace_once(launch, 'import time\n', 'import time\nimport threading\n')
    fd_statement = "fds={p.name:os.readlink(p) for p in (proc/'fd').iterdir()}"
    details = "fd_details={p.name:{'mode':oct(p.stat().st_mode&0o777),'uid':p.stat().st_uid,'links':p.stat().st_nlink,'size':p.stat().st_size,'target':os.readlink(p)} for p in (proc/'fd').iterdir()}"
    launch = replace_once(launch, fd_statement, fd_statement + '\n        ' + details)
    launch = replace_once(launch, "'fds':fds}", "'fds':fds,'fd_details':fd_details}")
    save_statement = "(root/'snapshot.json').write_text(json.dumps(receipt,indent=2)+'\\n');snapshots.append(str(root/'snapshot.json'))"
    spool_stat = "spool_details=(ROOT/'spool').stat();receipt['spool_directory_stat']={'mode':oct(spool_details.st_mode&0o777),'uid':spool_details.st_uid}"
    launch = replace_once(launch, save_statement, spool_stat + '\n    ' + save_statement)
    process_call = "completed=subprocess.run(argv,env={**env,'I12_APACHE_CLIENT_TOKEN':label},capture_output=True,timeout=20)"
    sampling = '''sampling_stop=threading.Event();sampling_errors=[]
    def sample_main():
        while not sampling_stop.wait(0.04):
            try:snapshot('during-main-'+str(time.monotonic_ns()))
            except (OSError,RuntimeError,AssertionError) as error:sampling_errors.append({'type':type(error).__name__,'message':str(error)})
    sampler=threading.Thread(target=sample_main)
    if label=='main':sampler.start()
    try:
        completed=subprocess.run(argv,env={**env,'I12_APACHE_CLIENT_TOKEN':label},capture_output=True,timeout=20)
    finally:
        sampling_stop.set()
        if label=='main':sampler.join(timeout=5)
        (ROOT/(label+'.sampler-errors.json')).write_text(json.dumps({'errors':sampling_errors,'stopped':not sampler.is_alive()},indent=2)+'\\n')'''
    return replace_once(launch, process_call, sampling)


def add_spool_probe(launch, default_capacity=False):
    if not default_capacity:
        launch = replace_once(launch, "'--spool-directory',ROOT/'spool'", "'--spool-directory',ROOT/'spool','--spool-capacity-bytes','8192','--spool-free-reserve-bytes','4096'")
    else:
        launch = replace_once(launch, DEFAULT_TIMEOUT_ARGUMENTS, "'--timeout-ms','15000'")
    launch = replace_once(launch, "if completed.returncode:raise RuntimeError", "if completed.returncode and label!='main':raise RuntimeError")
    start = launch.index("    snapshot('before-main');client('main'")
    end = launch.index("\n    client('neighbor'", start)
    existing = launch[start:end]
    probe = '''    holder_root=ROOT/'holder'
    holder_argv=['rtk','proxy','/usr/local/bin/python3','/mnt/fixtures/stock-spool-client.py','--port',str(port),'--directory',str(holder_root),'--length','4097']
    with (ROOT/'logs/holder.stdout').open('xb') as holder_stdout,(ROOT/'logs/holder.stderr').open('xb') as holder_stderr:
        holder=subprocess.Popen(holder_argv,stdout=holder_stdout,stderr=holder_stderr,env=env)
        try:
            deadline=time.monotonic()+10
            while True:
                if holder.poll() is not None:raise RuntimeError('independent holder exited before reservation')
                proc=Path('/proc')/str(actors['sidecar']['native_pid'])/'fd'
                held=[{'fd':fd.name,'size':fd.stat().st_size,'mode':oct(fd.stat().st_mode&0o777),'uid':fd.stat().st_uid,'links':fd.stat().st_nlink,'target':os.readlink(fd)} for fd in proc.iterdir() if fd.stat().st_nlink==0 and fd.stat().st_size==4097]
                if held and (holder_root/'ready.json').exists():break
                if time.monotonic()>=deadline:raise TimeoutError('actual held spool allocation not observed')
                time.sleep(0.01)
            (ROOT/'held-reservation.json').write_text(json.dumps({'monotonic_ns':time.monotonic_ns(),'actual_sidecar_pid':actors['sidecar']['native_pid'],'actual_fds':held,'backend_bytes_log_present':Path('/task/backend.jsonl').exists()},indent=2)+'\\n')
MAIN_SEQUENCE
        finally:
            if holder_root.exists():(holder_root/'release').touch(mode=0o600)
            try:holder.wait(timeout=5)
            except subprocess.TimeoutExpired:holder.terminate();holder.wait(timeout=5)
            (ROOT/'holder-process.json').write_text(json.dumps({'argv':holder_argv,'pid':holder.pid,'waited_exit':holder.returncode,'reaped':True},indent=2)+'\\n')
    time.sleep(0.2)
    client('readmission','POST','/i12/stock/readmitted',port);time.sleep(0.1);snapshot('after-readmission')'''
    probe = probe.replace('MAIN_SEQUENCE', '        ' + existing)
    if default_capacity:
        probe = probe.replace("'--length','4097'", "'--length','33554432','--count','8'")
        probe = probe.replace('==4097', '==33554432').replace("if held and (holder_root/", "if len(held)==8 and (holder_root/")
    return launch[:start] + probe + launch[end:]


def _launch_profile_and_configuration(launch, spec):
    if spec.get('profile_runtime_template'):
        template = spec['profile_runtime_template'].replace('/etc/modsecurity/no-crs-baseline.conf', '/task/lighttpd/rules.conf')
        template = template.replace('/var/log/lighttpd/msconnector-stock-' + spec['profile'] + '-events.jsonl', '/task/lighttpd/events.jsonl')
        launch = replace_once(launch, PRIVATE_RUNTIME_MODE, 'runtime.write_text(' + repr(template) + ')\nruntime.chmod(0o600)')
        launch = replace_once(launch, DEFAULT_TIMEOUT_ARGUMENTS, "'--timeout-ms','10000'")
        launch = replace_once(launch, "'--spool-directory',ROOT/'spool'", "'--spool-directory',ROOT/'spool','--spool-capacity-bytes','268435456','--spool-free-reserve-bytes','67108864'")
        launch = replace_once(launch, "'X-Request-Id: lighttpd-'", "'X-Modsec-Transaction-Id: lighttpd-'")
    if spec.get('configuration_probe'):
        config_case = spec['configuration_probe']
        mutation = {
            'valid_rules_file': '',
            'missing_rules_file': "runtime.write_text(runtime.read_text().replace(str(rules),str(ROOT/'missing-rules.conf')))\n",
            'invalid_rule_syntax': "rules.write_text(rules.read_text()+'NotAModSecurityDirective invalid\\n')\n",
            'unknown_config_key': "runtime.write_text(runtime.read_text()+'unknown_stock_i12_option=on\\n')\n",
            'invalid_boolean': "runtime.write_text(runtime.read_text().replace('enabled=on','enabled=not-a-boolean'))\n",
            'invalid_status': "runtime.write_text(runtime.read_text().replace('default_error_status=502','default_error_status=999'))\n",
            'invalid_size': "runtime.write_text(runtime.read_text().replace('max_header_count=64','max_header_count=-1'))\n",
            'unsafe_event_path': "(ROOT/'event-alias').symlink_to(ROOT/'rules.conf')\nruntime.write_text(runtime.read_text().replace(str(ROOT/'events.jsonl'),str(ROOT/'event-alias')))\n",
        }[config_case]
        mutation += "(ROOT/'configuration-input-observation.json').write_text(json.dumps({'config':str(runtime),'config_sha256':sha(runtime),'rules':str(rules),'rules_sha256':sha(rules),'missing_rules_lstat_absent':not (ROOT/'missing-rules.conf').exists(),'event_alias_is_symlink':(ROOT/'event-alias').is_symlink(),'fixture':" + repr(config_case) + "},indent=2)+'\\n')\n"
        launch = replace_once(launch, PRIVATE_RUNTIME_MODE, mutation + PRIVATE_RUNTIME_MODE)
        launch = replace_once(launch, '    return process\ndef starttime',
            "    (ROOT/(name+'.actual-start-command.json')).write_text(json.dumps({'argv':actual,'cwd':os.getcwd(),'actual_launcher_pid':process.pid,'executable_sha256':sha(Path(actual[2])),'runtime_config_sha256':sha(runtime),'rules_sha256':sha(rules)},indent=2)+'\\n')\n    return process\ndef starttime")
    return launch


def _launch_native_rules(launch, case, spec):
    if spec['response_content_type'] == CSV_MIME:
        launch = replace_once(launch, 'SecResponseBodyMimeType text/plain', 'SecResponseBodyMimeType text/plain text/csv')
    if 'above-former-connector-limit' in case:
        launch = launch.replace('BodyLimit 1048576', 'BodyLimit 2097152').replace('BodyNoFilesLimit 1048576', 'BodyNoFilesLimit 2097152')
    launch = replace_once(launch, "'SecRule REQUEST_METHOD \"@streq POST\" \"id:91042002,phase:2,pass,log,t:none,chain,msg:\\'test-only Lighttpd empty request P2 branch observed\\'\"',\n    'SecRule REQUEST_HEADERS:Content-Length \"@streq 0\" \"t:none,chain\"',\n    'SecRule REQUEST_BODY \"@rx ^$\" \"t:none\"',",
        repr('SecRule REQUEST_BODY "@contains i12-request-marker" "id:91042002,phase:2,pass,log,t:none,msg:\'exact original stock fixture P2 body marker reached\'"') + ',')
    if case == 'NEED-request-file':
        launch = replace_once(launch, 'SecRule REQUEST_BODY "@contains i12-request-marker"',
            'SecRule ARGS:payload "@contains i12-request-marker"')
        launch = replace_once(launch, PRIVATE_RULES_MODE,
            "rules.write_text(rules.read_text()+'SecTmpDir '+str(ROOT/'uploads')+'\\nSecUploadDir '+str(ROOT/'uploads')+'\\nSecUploadKeepFiles Off\\n')\nrules.chmod(0o600)")
    if 'canonical_rules' in spec:
        canonical_rules = spec['canonical_rules'].replace('@@AUDIT_LOG@@', '/task/lighttpd/audit/native-audit.log').replace('@@AUDIT_LOG_DIR@@', '/task/lighttpd/audit')
        launch = replace_once(launch, PRIVATE_RULES_MODE,
            "rules.write_text(rules.read_text()+" + repr('\n' + canonical_rules) + ")\nrules.chmod(0o600)")
        extra_headers = [item for name, value in spec['request_headers']
                         if name.lower() != 'content-type' for item in ('-H', str(name) + ': ' + str(value))]
        launch = replace_once(launch, POST_ARGUMENTS, MAIN_ARGUMENTS + repr(extra_headers) + POST_ARGUMENTS_LINE)
        if spec.get('resolved_source_case') in ('transaction_id_generated_or_fallback', 'transaction_id_present'):
            launch = replace_once(launch, "'-H','X-Request-Id: lighttpd-'+route+'-'+label", "*(['-H','X-Request-Id: lighttpd-'+route+'-'+label] if label!='main' else [])")
        if spec.get('resolved_source_case') == 'transaction_id_present':
            launch = replace_once(launch, 'transaction_id_header=x-request-id', 'transaction_id_header=x-modsec-transaction-id')
        if spec.get('sequence_probe'):
            if spec['sequence_probe'] == 'allow-deny-allow':
                launch = replace_once(launch, MAIN_ARGUMENTS, "if label=='sequence-deny':argv+=['-H','X-Modsec-Smoke: block']\n    if label=='main':argv+=")
                sequence_call = "    client('sequence-deny','GET','/no-crs/deny',port)\n    snapshot('after-sequence-deny')\n"
            else:
                sequence_call = "    client('sequence-second','GET'," + repr(spec['path']) + ",port)\n    snapshot('after-sequence-second')\n"
            launch = replace_once(launch, NEIGHBOR_CALL, sequence_call + NEIGHBOR_CALL)
    return launch


def _launch_sink_fault(launch, spec):
    if spec.get('sink_fault'):
        env_prefix = ENVIRONMENT_PREFIX
        launch = replace_once(launch, env_prefix, env_prefix +
            "'MSCONNECTOR_LIGHTTPD_SINK_FAULT':" + repr(spec['sink_fault']) + "," +
            "'MSCONNECTOR_LIGHTTPD_SINK_FAULT_TRACE':'/task/sink-fault.jsonl',")
        rule = 'SecRule REQUEST_URI "@streq ' + spec['path'] + '" "id:91042003,phase:1,deny,status:403,log,t:none,msg:\'native decision precedes actual test sink I/O fault\'"'
        if spec['sink_fault'] != 'close':
            launch = replace_once(launch, PRIVATE_RULES_MODE,
                'rules.write_text(rules.read_text()+' + repr(rule + '\n') + ')\nrules.chmod(0o600)')
        else:
            launch = replace_once(launch, 'import time\n', 'import time\nimport socket\n')
            launch = replace_once(launch, ENVIRONMENT_PREFIX, "env={**os.environ,'MSCONNECTOR_LIGHTTPD_SINK_STOP':'/task/lighttpd/close-stop',")
            stop = "\n    (ROOT/'close-stop').touch(mode=0o600)\n    with socket.create_connection(('127.0.0.1',port),timeout=5) as trigger:\n        trigger.settimeout(5);actual_stop_bytes=trigger.recv(4096)\n    actors['sidecar']['process'].wait(timeout=5)\n    (ROOT/'actual-lifetime-stop.json').write_text(json.dumps({'actual_stop_bytes':len(actual_stop_bytes),'waited_sidecar_exit':actors['sidecar']['process'].returncode,'capture_accept_stop_injected':True,'HTTP_transaction_invented':False},indent=2)+'\\n')"
            launch = replace_once(launch, "snapshot('after-neighbor')", "snapshot('after-neighbor')" + stop)
    return launch


def _launch_caller_and_transport(launch, spec):
    if spec.get('diagnostic_boundary_fault'):
        launch = replace_once(launch, ENVIRONMENT_PREFIX, ENVIRONMENT_PREFIX +
            "'MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT':" + repr(spec['diagnostic_boundary_fault']) + "," +
            "'MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT_LOG':'/task/diagnostic-boundary-fault.jsonl',")
        launch = replace_once(launch, DEFAULT_ERROR_STATUS, 'default_error_status=500')
    if spec.get('configured_event_json_limit'):
        launch = replace_once(launch, DEFAULT_ERROR_STATUS,
            'default_error_status=502\\nmax_event_json_bytes=' + str(spec['configured_event_json_limit']))
    if spec.get('pointer_fault'):
        launch = replace_once(launch, ENVIRONMENT_PREFIX, ENVIRONMENT_PREFIX +
            "'MSCONNECTOR_LIGHTTPD_POINTER_FAULT':" + repr(spec['pointer_fault']) + "," +
            "'MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT_LOG':'/task/pointer-fault.jsonl',")
        launch = replace_once(launch, DEFAULT_ERROR_STATUS, 'default_error_status=500')
    if spec.get('backend_incomplete') or spec.get('client_abort_mode') or spec.get('allow_main_transport_failure'):
        launch = replace_once(launch, 'if completed.returncode:raise RuntimeError(',
            "if completed.returncode and label!='main':raise RuntimeError(")
    if spec.get('client_abort_mode'):
        launch = replace_once(launch, ENVIRONMENT_PREFIX, "env={**os.environ,'MSCONNECTOR_LIGHTTPD_TRANSPORT_OBSERVER':'/task/transport-api.jsonl',")
        launch = replace_once(launch, POST_ARGUMENTS,
            MAIN_ARGUMENTS + repr(['--i12-abort-after-first-entity', spec['client_abort_mode']]) + POST_ARGUMENTS_LINE)
    return launch


def _launch_header_mapping(launch, spec):
    if spec.get('mapping_probe'):
        probe = spec['mapping_probe']
        if probe.startswith('header_count_'):
            extras = [item for index in range(59 if probe.endswith('at_limit') else 60)
                for item in ('-H', 'X-I12-' + str(index) + ': v')]
            launch = replace_once(launch, POST_ARGUMENTS,
                MAIN_ARGUMENTS + repr(extras) + POST_ARGUMENTS_LINE)
        elif probe.startswith('total_header_bytes_'):
            launch = replace_once(launch, 'max_total_header_bytes=65536', 'max_total_header_bytes=512')
            client_extra = "\n    if label=='main':argv+=['--i12-header-byte-boundary','" + ('512' if probe.endswith('at_limit') else '513') + "']"
            launch = replace_once(launch, "    if method=='POST':argv+=", client_extra + POST_ARGUMENTS_LINE)
        else:
            launch = replace_once(launch, POST_ARGUMENTS,
                MAIN_ARGUMENTS + repr(['--i12-framing-case', probe]) + POST_ARGUMENTS_LINE)
    return launch


def _prepare_launcher(fixtures, case, spec, output):
    launch_path = fixtures / LAUNCHER_FILE
    launch = launch_path.read_text()
    start = launch.index("if route=='stock-sidecar':\n    stock_spec=")
    end = launch.index('text += [', start)
    launch = launch[:start] + "# Exact current observed binary/source proof is sealed in fixture-contract.json.\n" + launch[end:]
    launch = launch.replace('NEED-request-empty', case)
    run_id = '20261015-stock-' + hashlib.sha256(str(output).encode()).hexdigest()[:12] + '-'
    launch = replace_once(launch, "'20261014T182400Z-lighttpd-empty-'", repr(run_id))
    launch = replace_once(launch, "body.write_bytes(b'')", "body.write_bytes(bytes.fromhex(" + repr(spec['request_hex']) + "))")
    launch = replace_once(launch, "client('main','POST','/i12/lighttpd/empty',port)",
                          "client('main'," + repr(spec['method']) + ',' + repr(spec['path']) + ",port)")
    if spec['request_content_type'] is None:
        launch = replace_once(launch, "'-H','Content-Type: text/plain',", '')
    else:
        launch = replace_once(launch, "Content-Type: text/plain", 'Content-Type: ' + spec['request_content_type'])
    launch = replace_once(launch, "'phase4_mode=safe'", repr('phase4_mode=' + ('strict' if spec['profile'] == 'all' else spec['profile'])))
    if spec.get('explicit_phase4_mode'):
        launch = replace_once(launch, "'phase4_mode=off'", repr('phase4_mode=' + spec['explicit_phase4_mode']))
    if case == 'NEED-first-byte-before-late-error':
        launch = replace_once(launch, "text += [", "text += ['server.stream-response-body = 1']\ntext += [")
    launch = _launch_profile_and_configuration(launch, spec)
    launch = _launch_native_rules(launch, case, spec)
    launch = _launch_sink_fault(launch, spec)
    launch = _launch_caller_and_transport(launch, spec)
    launch = _launch_header_mapping(launch, spec)
    if spec.get('backend_delay_before_headers'):
        launch = replace_once(launch, DEFAULT_TIMEOUT_ARGUMENTS, "'--timeout-ms','100'")
        launch = replace_once(launch, NEIGHBOR_CALL, "    time.sleep(1)\n    client('neighbor','GET'")
    if spec['sample_live_spool']:
        launch = add_live_sampler(launch)
    if spec.get('spool_probe'):
        launch = add_spool_probe(launch, spec.get('default_capacity_probe', False))
        shutil.copyfile(regular(REPO / 'ci/runtime/lifecycle/i12/lighttpd/stock_spool_client.py'), fixtures / 'stock-spool-client.py')
    launch_path.write_text(launch)


def _prepare_client(fixtures, spec):
    client_path = fixtures / CLIENT_FILE
    client = regular(REPO / 'ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py').read_text()
    (fixtures / 'lighttpd_capture_response.py').write_text(response_helper_text())
    if spec['delayed_request']:
        split = str(spec.get('explicit_request_split_bytes', 4096))
        client = replace_once(client, 'connection.sendall(request)',
            "boundary=request.index(b'\\r\\n\\r\\n')+4+" + split + "\n        connection.sendall(request[:boundary])\n        time.sleep(0.2)\n        connection.sendall(request[boundary:])")
    client_path.write_text(client)


def _prepare_backend(fixtures, case, spec):
    backend_path = fixtures / BACKEND_LAUNCHER_FILE
    backend = backend_path.read_text()
    backend = replace_once(backend, "b'apx-eos-response-payload'", 'bytes.fromhex(' + repr(spec['response_hex']) + ')')
    backend = replace_once(backend, "('Content-Type','text/plain')", repr(('Content-Type', spec['response_content_type'])))
    if spec.get('response_headers'):
        original_response_fixture = 'module.ResponseFixture(200,' + repr((('Content-Type', spec['response_content_type']),)) + ')'
        new_headers = (('Content-Type', spec['response_content_type']), *map(tuple, spec['response_headers']))
        backend = replace_once(backend, original_response_fixture, 'module.ResponseFixture(200,' + repr(new_headers) + ')')
    if case == 'NEED-response-file':
        statement = 'module.Handler.body_bytes=bytes.fromhex(' + repr(spec['response_hex']) + ')'
        backend = replace_once(backend, statement,
            "import hashlib,json,stat,time\n"
            "response_file=Path('/task/backend-response.input');response_file.write_bytes(bytes.fromhex(" + repr(spec['response_hex']) + "));response_file.chmod(0o600)\n"
            "response_fd=os.open(response_file,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n"
            "try:\n"
            " details=os.fstat(response_fd)\n"
            " assert stat.S_ISREG(details.st_mode) and details.st_uid==os.geteuid() and stat.S_IMODE(details.st_mode)==0o600 and details.st_nlink==1\n"
            " module.Handler.body_bytes=os.read(response_fd,2097153)\n"
            " assert len(module.Handler.body_bytes)<=2097152\n"
            " file_observation={'actual_fd':response_fd,'mode':oct(stat.S_IMODE(details.st_mode)),'uid':details.st_uid,'links':details.st_nlink,'inode':details.st_ino,'actual_read_bytes':len(module.Handler.body_bytes),'actual_read_sha256':hashlib.sha256(module.Handler.body_bytes).hexdigest(),'monotonic_ns':time.monotonic_ns()}\n"
            "finally:os.close(response_fd)\n"
            "Path('/task/backend-response-file.json').write_text(json.dumps(file_observation,indent=2)+'\\n')")
    backend = replace_once(backend, "server=HTTPServer(",
        "actual_main_response=module.Handler.body_bytes\nmodule.Handler.body_bytes=property(lambda self:actual_main_response if self.path==" + repr(spec['path']) + " else b'healthy')\nserver=HTTPServer(")
    backend_path.write_text(backend)
    if spec.get('backend_delay_before_headers'):
        backend_observer = fixtures / BACKEND_OBSERVER_FILE
        backend_observer.write_text(replace_once(backend_observer.read_text(),
            '    def _send_fixture(self, *, include_body: bool) -> None:',
            '    def _send_fixture(self, *, include_body: bool) -> None:\n'
            '        if self.path == ' + repr(spec['path']) + ':\n'
            '            import time\n            time.sleep(0.5)'))
    if case in CANONICAL_RESPONSE_HEADER_CASES or spec.get('canonical_catalog_phase') == 3:
        backend_observer = fixtures / BACKEND_OBSERVER_FILE
        backend_observer.write_text(replace_once(backend_observer.read_text(),
            '        for name, value in self.fixture.headers:\n            self.send_header(name, value)',
            '        for name, value in self.fixture.headers:\n'
            '            if self.path == ' + repr(spec['path']) + ' or name.lower() == "content-type":\n'
            '                self.send_header(name, value)'))
    if spec.get('backend_incomplete'):
        backend_observer = fixtures / BACKEND_OBSERVER_FILE
        observed_backend = replace_once(backend_observer.read_text(), 'import html\n', 'import html\nimport time\n')
        observed_backend = replace_once(observed_backend,
            'self.send_header("Content-Length", str(len(body)))',
            'self.send_header("Content-Length", str(len(body) + (5 if self.path == ' + repr(spec['path']) + ' else 0)))')
        observed_backend = replace_once(observed_backend,
            '            self.wfile.write(body)',
            '            self.wfile.write(body)\n            self.wfile.flush()\n            if self.path == ' + repr(spec['path']) + ': time.sleep(0.2)')
        observed_backend = add_backend_header_boundary(observed_backend)
        observed_backend = replace_once(observed_backend,
            '            if self.path == ' + repr(spec['path']) + ': time.sleep(0.2)',
            '            if self.path == ' + repr(spec['path']) + ':\n'
            '                time.sleep(0.2)\n'
            "                self._i12_capture_boundary='response_handler_before_return'\n"
            "                _apache_lifecycle_capture(self,b'')")
        backend_observer.write_text(observed_backend)
    if spec.get('split_backend_response'):
        backend_observer = fixtures / BACKEND_OBSERVER_FILE
        body_writer = '            self.wfile.write(body)'
        split = str(spec.get('backend_split_bytes', 5))
        split_writer = ('            self.wfile.write(body[:' + split + '])\n'
            '            self.wfile.flush()\n'
            '            time.sleep(0.2)\n'
            '            self.wfile.write(body[' + split + ':])')
        observed_backend = replace_once(backend_observer.read_text(), body_writer, split_writer)
        observed_backend = replace_once(observed_backend, 'import html\n', 'import html\nimport time\n')
        if spec['response_content_type'] is None:
            observed_backend = replace_once(observed_backend,
                '        for name, value in self.fixture.headers:\n            self.send_header(name, value)',
                '        for name, value in self.fixture.headers:\n            if value is not None:\n                self.send_header(name, value)')
        backend_observer.write_text(observed_backend)
    if case == 'NEED-replay-only-after-native-p2-allow':
        backend_observer = fixtures / BACKEND_OBSERVER_FILE
        backend_observer.write_text(add_backend_header_boundary(backend_observer.read_text()))


def _copy_capture_images(artifacts, previous, observed_sidecar, observer_binding):
    if (observed_sidecar is None) != (observer_binding is None):
        raise ValueError('a new observed image requires its separate build binding')
    for relative in ('stock-host/bin/lighttpd', 'lighttpd-stock-sidecar'):
        destination = artifacts / ('sidecar/lighttpd-stock-sidecar' if relative == 'lighttpd-stock-sidecar' else relative)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        original_image = observed_sidecar if relative == 'lighttpd-stock-sidecar' and observed_sidecar else previous / relative
        shutil.copyfile(regular(original_image), destination)
        destination.chmod(0o555)
    for path in (previous / 'stock-host/lib').iterdir():
        target = artifacts / 'stock-host/lib' / path.name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(regular(path), target)
        target.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)



def prepare(output, case, inherited, controller_run, observed_sidecar=None, observer_binding=None, native_audit_json=False):
    storage_root(EXTERNAL)
    output = Path(output).absolute()
    if '..' in output.parts or not output.is_relative_to(controller_run):
        raise ValueError('output must be below current controller run root')
    if any(path.is_symlink() for path in (*output.parents, output)):
        raise ValueError('output alias forbidden')
    output.mkdir(mode=0o700, parents=True)
    spec = fixture(case)
    if native_audit_json:
        if 'canonical_rules' not in spec:
            raise ValueError('native JSON audit control requires an existing canonical rule fixture')
        spec['canonical_rules'] += '\nSecAuditLogFormat JSON\n'
        spec['native_audit_format_control'] = 'Actual native SDK JSON exporter; original rules and requests retained, no projected Common event.'
    row = next(row for row in json.loads(inherited.read_text())['rows']
               if row['run_scoped_case_id'] == 'I12::lighttpd-stock-sidecar::' + case)
    original = row.get('original_selected_requirement', row.get('selected_requirement'))
    fixtures = output / 'fixtures'
    fixtures.mkdir(mode=0o700)
    artifacts = output / 'artifacts'
    artifacts.mkdir(mode=0o700)
    previous = PREVIOUS / 'stock/nonroot-v2/artifacts'
    _copy_capture_images(artifacts, previous, observed_sidecar, observer_binding)
    (artifacts / 'sidecar/stock-sidecar-artifact.manifest').write_text(
        'sidecar_path=/var/tmp/codex/ModSecurity-conector/stock-qualification-owned/sidecar/lighttpd-stock-sidecar\n')
    source = output / 'source'
    source.mkdir(mode=0o700)
    (source / 'ci/runtime/common').mkdir(parents=True)
    dependency = REPO / 'ci/runtime/common/response_fixture_omission.py'
    shutil.copyfile(regular(dependency), source / 'ci/runtime/common/response_fixture_omission.py')
    old_fixtures = OLD / 'lighttpd-next-empty/stock-sidecar/fixtures'
    for name in (LAUNCHER_FILE, CLIENT_FILE, BACKEND_OBSERVER_FILE, BACKEND_LAUNCHER_FILE):
        shutil.copyfile(regular(old_fixtures / name), fixtures / name)
    _prepare_launcher(fixtures, case, spec, output)
    _prepare_client(fixtures, spec)
    _prepare_backend(fixtures, case, spec)
    independent = json.loads((old_fixtures / FIXTURE_CONTRACT_FILE).read_text())['independent_sources']
    preserved_sources = {}
    for label, original_source in (
            ('actual_client_variant_source', REPO / 'ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py'),
            ('actual_fixture_producer_source', Path(__file__))):
        frozen = fixtures / ('producer-' + sha(original_source) + '.py')
        shutil.copyfile(regular(original_source), frozen)
        preserved_sources[label] = {'path': str(frozen), 'sha256': sha(frozen),
            'working_path': str(original_source), 'scope': 'Preserved preparation source; executed launcher/client have separate sealed binding.'}
    contract = {'schema': 'lighttpd-original-stock-fixture-v1', 'original_selected_requirement': original,
                'fixture': spec, 'independent_sources': independent,
                'original_oracle': original['expected_oracle'],
                'build_source_binding': json.loads((PREVIOUS / 'stock/capture-04/build-binding.json').read_text()),
                'nonroot_original_helper_binding': json.loads((PREVIOUS / 'stock/nonroot-input/provenance.json').read_text()),
                'original_launcher_sha256': sha(old_fixtures / LAUNCHER_FILE),
                'original_client_sha256': sha(old_fixtures / CLIENT_FILE),
                **preserved_sources,
                'launcher_changes': ['exact selected case/body/headers/profile/marker',
                    'replace historical source metadata check with complete current compiled source/binary hashes'],
                'full_lifecycle_qualified': False}
    head_command = ['rtk', 'proxy', 'git', '-C', str(REPO), 'rev-parse', 'HEAD']
    head = subprocess.run(head_command, check=True, capture_output=True, text=True).stdout.strip()
    contract['actual_checkout_head_at_preparation'] = head
    contract['checkout_head_scope'] = 'Git preparation metadata; compiled product identity is exclusively the separately hashed build input/object/image binding, including dirty source bytes.'
    contract['checkout_head_command'] = head_command
    if observer_binding:
        binding = json.loads(read_text(observer_binding))
        if binding.get('binary_sha256') != sha(observed_sidecar) or binding.get('exit') != 0:
            raise ValueError('new observed sidecar image/build receipt mismatch')
        contract['observer_extension_build_binding'] = binding
        contract['observer_extension_receipt_reference'] = {'path': str(observer_binding), 'sha256': sha(observer_binding)}
    save(fixtures / FIXTURE_CONTRACT_FILE, contract)
    artifact_binding = seal_tree(artifacts, output / ARTIFACT_LEDGER_FILE)
    shutil.copyfile(regular(output / ARTIFACT_LEDGER_FILE), fixtures / ARTIFACT_LEDGER_FILE)
    bindings = []
    for tree, target in ((fixtures, '/mnt/fixtures'), (source, '/mnt/src')):
        item = seal_tree(tree, output / (tree.name + '-ledger.json'))
        item['target'] = target
        bindings.append(item)
    artifact_binding['target'] = '/mnt/artifacts'
    bindings.append(artifact_binding)
    admission = {'argv': ['/usr/local/bin/python3', '/mnt/fixtures/launch.py', 'stock-sidecar'],
                 'bindings': bindings, 'environment': {}, 'mode': 'nonroot',
                 'resource_limits': {'memory_bytes': 2147483648, 'output_bytes': 536870912, 'processes': 256},
                 'timeout_seconds': 180, 'setup_timeout_seconds': 120}
    save(output / ADMISSION_SPEC_FILE, admission)
    (output / ADMISSION_SPEC_FILE).chmod(0o444)
    return output / ADMISSION_SPEC_FILE


def copy_input_tree(source, destination):
    if any(path.is_symlink() for path in (*source.parents, source)):
        raise ValueError('source tree alias forbidden')
    destination.mkdir(mode=0o700, parents=True)
    for path in source.rglob('*'):
        if path.is_symlink():
            raise ValueError('source tree alias forbidden')
        target = destination / path.relative_to(source)
        if path.is_dir():
            target.mkdir(mode=0o700, exist_ok=True)
        else:
            shutil.copyfile(regular(path), target)
            if path.stat().st_mode & 0o111:
                target.chmod(0o555)


def prepare_batch(output, cases, inherited, controller_run, observed_sidecar=None, observer_binding=None, native_audit_json=False):
    """Amortize trusted namespace setup; every case retains separate actors/data."""
    storage_root(EXTERNAL)
    output = Path(output).absolute()
    if '..' in output.parts or not output.is_relative_to(controller_run):
        raise ValueError('output must be below current controller run root')
    if any(path.is_symlink() for path in (*output.parents, output)):
        raise ValueError('output alias forbidden')
    output.mkdir(mode=0o700, parents=True)
    combined_fixtures = output / 'fixtures'
    combined_artifacts = output / 'artifacts'
    for tree in (combined_fixtures, combined_artifacts):
        tree.mkdir(mode=0o700)
    for case in cases:
        child = output / 'individual-inputs' / case
        prepare(child, case, inherited, controller_run, observed_sidecar, observer_binding, native_audit_json)
        fixtures = combined_fixtures / case
        artifacts = combined_artifacts / case
        copy_input_tree(child / 'fixtures', fixtures)
        copy_input_tree(child / 'artifacts', artifacts)
        launcher = fixtures / LAUNCHER_FILE
        text = launcher.read_text().replace(FIXTURE_PREFIX, FIXTURE_PREFIX + case + '/')
        text = text.replace('/mnt/artifacts/', '/mnt/artifacts/' + case + '/')
        text = text.replace("Path('/mnt/artifacts')", "Path('/mnt/artifacts/" + case + "')")
        text = text.replace(TASK_PREFIX, TASK_PREFIX + case + '/')
        launcher.write_text(text)
        client = fixtures / CLIENT_FILE
        client.write_text(client.read_text().replace(TASK_PREFIX, TASK_PREFIX + case + '/'))
        backend = fixtures / BACKEND_LAUNCHER_FILE
        backend.write_text(backend.read_text().replace(FIXTURE_PREFIX, FIXTURE_PREFIX + case + '/').replace(TASK_PREFIX, TASK_PREFIX + case + '/'))
        manifest = artifacts / 'sidecar/stock-sidecar-artifact.manifest'
        manifest.write_text(manifest.read_text().replace('/stock-qualification-owned/', '/stock-qualification-owned/' + case + '/'))
        save(fixtures / ARTIFACT_LEDGER_FILE, {'files': {str(path.relative_to(artifacts)): sha(path)
             for path in artifacts.rglob('*') if path.is_file()}})
        contract_path = fixtures / FIXTURE_CONTRACT_FILE
        contract = json.loads(contract_path.read_text())
        contract['batch_case_namespace'] = {'case_relative_data': case,
            'actors_separate_per_case': True, 'same_namespace_sequential_execution': True,
            'relocated_launcher_sha256': sha(launcher)}
        save(contract_path, contract)
    source = output / 'source'
    copy_input_tree(output / 'individual-inputs' / cases[0] / 'source', source)
    dispatcher = combined_fixtures / 'launch-batch.py'
    dispatcher.write_text('''import json,os,subprocess
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==os.getegid()==65534
CASES=CASES_PLACEHOLDER
results=[]
for case in CASES:
 root=Path('/task')/case;root.mkdir(mode=0o700)
 argv=['rtk','proxy','/usr/local/bin/python3','/mnt/fixtures/'+case+'/launch.py','stock-sidecar']
 with (root/'driver.stdout').open('xb') as stdout,(root/'driver.stderr').open('xb') as stderr:
  result=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=180)
 receipt={'case':case,'argv':argv,'waited_exit':result.returncode}
 (root/'driver-receipt.json').write_text(json.dumps(receipt,indent=2)+'\\n')
 results.append(receipt)
Path('/task/batch-result.json').write_text(json.dumps(results,indent=2)+'\\n')
raise SystemExit(1 if any(row['waited_exit'] for row in results) else 0)
'''.replace('CASES_PLACEHOLDER', repr(cases)))
    bindings = []
    for tree, target in ((combined_fixtures, '/mnt/fixtures'), (combined_artifacts, '/mnt/artifacts'), (source, '/mnt/src')):
        item = seal_tree(tree, output / (tree.name + '-ledger.json'))
        item['target'] = target
        bindings.append(item)
    admission = {'argv': ['/usr/local/bin/python3', '/mnt/fixtures/launch-batch.py'],
        'bindings': bindings, 'environment': {}, 'mode': 'nonroot',
        'resource_limits': {'memory_bytes': 2147483648, 'output_bytes': 1073741824, 'processes': 256},
        'timeout_seconds': 1800, 'setup_timeout_seconds': 120}
    save(output / ADMISSION_SPEC_FILE, admission)
    (output / ADMISSION_SPEC_FILE).chmod(0o444)
    return output / ADMISSION_SPEC_FILE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--case', action='append', required=True)
    parser.add_argument('--inherited', required=True, type=Path)
    parser.add_argument('--controller-run', required=True, type=Path)
    parser.add_argument('--observed-sidecar', type=Path)
    parser.add_argument('--observer-binding', type=Path)
    parser.add_argument('--native-audit-json', action='store_true')
    args = parser.parse_args()
    if len(args.case) == 1:
        result = prepare(args.output, args.case[0], args.inherited, args.controller_run,
                         args.observed_sidecar, args.observer_binding, args.native_audit_json)
    else:
        result = prepare_batch(args.output, args.case, args.inherited, args.controller_run,
                               args.observed_sidecar, args.observer_binding, args.native_audit_json)
    print(result)


if __name__ == '__main__':
    main()
